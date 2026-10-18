from __future__ import annotations
import re
from typing import Optional

from .client import SupabaseClient
from .models import ColumnInfo, RPCFunction, StorageBucket, TableInfo


def parse_openapi_columns(spec: dict, table_name: str) -> list[ColumnInfo]:
    columns = []
    definitions = spec.get("definitions", {})
    table_def = definitions.get(table_name, {})
    properties = table_def.get("properties", {})
    required = set(table_def.get("required", []))
    pk_fields = set()

    # PostgREST marks primary keys with x-constraint or description
    for col_name, col_def in properties.items():
        desc = col_def.get("description", "")
        if "Primary Key" in desc or col_def.get("x-is-pk"):
            pk_fields.add(col_name)

    for col_name, col_def in properties.items():
        col_type = col_def.get("type", col_def.get("format", "unknown"))
        if isinstance(col_type, list):
            col_type = col_type[0]
        columns.append(
            ColumnInfo(
                name=col_name,
                type=str(col_type),
                nullable=col_name not in required,
                is_primary=col_name in pk_fields or col_name == "id",
            )
        )
    return columns


def _columns_from_rows(rows: list[dict]) -> list[ColumnInfo]:
    """Infer columns from sample rows when no schema is available."""
    if not rows or not isinstance(rows[0], dict):
        return []
    return [
        ColumnInfo(
            name=name,
            type=type(value).__name__ if value is not None else "unknown",
            nullable=True,
            is_primary=name == "id",
        )
        for name, value in rows[0].items()
    ]


def probe_tables(client: SupabaseClient, names: list[str]) -> list[TableInfo]:
    """Probe table names directly (e.g. names scraped from JS). 404 means the table doesn't exist."""
    tables = []
    for name in names:
        resp = client.query_table(name, limit=5)
        if resp.status_code == 404:
            continue
        table = TableInfo(name=name)
        if resp.status_code == 200:
            table.accessible = True
            try:
                table.sample_data = resp.json()
            except Exception:
                table.sample_data = []
            table.columns = _columns_from_rows(table.sample_data)
        tables.append(table)
    return tables


# PostgREST >= 12 suggests the closest real name for unknown tables/functions:
#   PGRST205 hint: "Perhaps you meant the table 'public.profiles'"
#   PGRST202 hint: "Perhaps you meant to call the function public.get_user(uid)"
_RE_HINT_TABLE = re.compile(r"the table '(?:[A-Za-z0-9_]+\.)?([A-Za-z0-9_]+)'")
_RE_HINT_FUNC = re.compile(r"the function (?:[A-Za-z0-9_]+\.)?([A-Za-z0-9_]+)")


def _hint(resp) -> str:
    try:
        return (resp.json() or {}).get("hint") or ""
    except Exception:
        return ""


def leak_table_names(client: SupabaseClient, seeds: list[str]) -> list[str]:
    """Discover real table names by probing seeds: hits are returned as-is, misses via the PGRST205 hint."""
    found: list[str] = []
    for seed in seeds:
        resp = client.query_table(seed, limit=1)
        if resp.status_code != 404:
            name = seed
        else:
            m = _RE_HINT_TABLE.search(_hint(resp))
            if not m:
                continue
            name = m.group(1)
        if name not in found:
            found.append(name)
    return found


def leak_rpc_names(client: SupabaseClient, seeds: list[str]) -> list[str]:
    """Discover real function names from PGRST202 hints.

    Seeds are mangled so the probed name never exists — discovery must not execute
    a real function; the hint still names the closest real one.
    """
    found: list[str] = []
    for seed in seeds:
        resp = client.call_rpc(f"{seed}_zzsupascan", {})
        m = _RE_HINT_FUNC.search(_hint(resp))
        if m and m.group(1) not in found:
            found.append(m.group(1))
    return found


def enumerate_tables(client: SupabaseClient, hint_names: Optional[list[str]] = None) -> list[TableInfo]:
    resp = client.get_openapi_spec()
    if resp.status_code != 200:
        return probe_tables(client, hint_names or [])

    try:
        spec = resp.json()
    except Exception:
        return []

    tables = []
    paths = spec.get("paths", {})
    for path, path_def in paths.items():
        # Skip RPC paths
        if path.startswith("/rpc/"):
            continue
        table_name = path.lstrip("/")
        if not table_name:
            continue

        columns = parse_openapi_columns(spec, table_name)
        table = TableInfo(name=table_name, columns=columns)

        # Try to fetch sample data
        data_resp = client.query_table(table_name, limit=5)
        if data_resp.status_code == 200:
            table.accessible = True
            try:
                table.sample_data = data_resp.json()
            except Exception:
                table.sample_data = []
        else:
            table.accessible = False

        tables.append(table)
    return tables


def probe_rpc_functions(client: SupabaseClient, names: list[str]) -> list[RPCFunction]:
    """Probe RPC names directly. 404 means the function doesn't exist."""
    rpcs = []
    for name in names:
        rpc_resp = client.call_rpc(name, {})
        if rpc_resp.status_code == 404:
            continue
        rpcs.append(
            RPCFunction(
                name=name,
                accessible=rpc_resp.status_code not in (401, 403),
                response_status=rpc_resp.status_code,
            )
        )
    return rpcs


def enumerate_rpc_functions(client: SupabaseClient, hint_names: Optional[list[str]] = None) -> list[RPCFunction]:
    try:
        resp = client.get_openapi_spec()
    except Exception:
        return []
    if resp.status_code != 200:
        return probe_rpc_functions(client, hint_names or [])

    try:
        spec = resp.json()
    except Exception:
        return []

    rpcs = []
    paths = spec.get("paths", {})
    for path, path_def in paths.items():
        if not path.startswith("/rpc/"):
            continue
        name = path[len("/rpc/"):]
        if not name:
            continue

        # Extract parameters from POST body schema
        parameters = {}
        post_def = path_def.get("post", {})
        params_schema = post_def.get("parameters", [])
        for param in params_schema:
            if param.get("in") == "body":
                schema = param.get("schema", {})
                parameters = schema.get("properties", {})
                break

        rpc_resp = client.call_rpc(name, {})
        accessible = rpc_resp.status_code not in (401, 403)

        rpcs.append(
            RPCFunction(
                name=name,
                parameters=parameters,
                accessible=accessible,
                response_status=rpc_resp.status_code,
            )
        )
    return rpcs


def enumerate_buckets(client: SupabaseClient) -> list[StorageBucket]:
    try:
        resp = client.list_buckets()
    except Exception:
        return []
    if resp.status_code != 200:
        return []

    try:
        raw_buckets = resp.json()
    except Exception:
        return []

    if not isinstance(raw_buckets, list):
        return []

    buckets = []
    for b in raw_buckets:
        name = b.get("name", b.get("id", ""))
        is_public = b.get("public", False)

        obj_resp = client.list_bucket_objects(name)
        accessible = obj_resp.status_code == 200
        file_count = 0
        if accessible:
            try:
                objects = obj_resp.json()
                file_count = len(objects) if isinstance(objects, list) else 0
            except Exception:
                pass

        buckets.append(
            StorageBucket(
                name=name,
                public=is_public,
                accessible=accessible,
                file_count=file_count,
            )
        )
    return buckets
