"""Default names probed when the OpenAPI spec is closed and client JS references nothing.

Each probe either hits a real table/function or, on PostgREST >= 12, returns a
"Perhaps you meant ..." hint naming the closest real one — so the list only needs
to land near real names, not on them.
"""
from __future__ import annotations
from pathlib import Path
from typing import Optional

TABLES = [
    # identity
    "users", "user", "profiles", "profile", "accounts", "account", "members", "customers",
    "clients", "admins", "roles", "user_roles", "permissions", "teams", "team_members",
    "organizations", "orgs", "workspaces", "tenants", "companies", "invites", "invitations",
    "sessions", "api_keys", "tokens", "devices", "settings", "user_settings", "preferences",
    # money
    "wallets", "wallet", "transactions", "payments", "invoices", "orders", "order_items",
    "subscriptions", "plans", "prices", "products", "carts", "cart_items", "coupons",
    "balances", "transfers", "withdrawals", "deposits", "credits", "refunds", "billing",
    "portfolios", "portfolio", "assets", "positions", "holdings", "trades", "stocks",
    "dividends", "investments", "operations", "brokers", "quotes",
    # content
    "posts", "comments", "messages", "chats", "conversations", "notifications", "events",
    "files", "documents", "uploads", "images", "media", "attachments", "categories", "tags",
    "reviews", "ratings", "likes", "favorites", "bookmarks", "feedback", "tickets",
    "articles", "pages", "news", "projects", "tasks", "items", "leads", "contacts",
    # ops
    "logs", "audit_logs", "activity", "analytics", "metrics", "reports", "jobs", "queue",
    "webhooks", "integrations", "feature_flags", "flags", "config", "secrets", "migrations",
    "addresses", "locations", "countries", "referrals", "waitlist", "newsletter",
    # pt-BR
    "usuarios", "usuario", "perfis", "perfil", "clientes", "contas", "empresas", "carteiras",
    "carteira", "transacoes", "pagamentos", "assinaturas", "planos", "pedidos", "produtos",
    "ativos", "investimentos", "operacoes", "proventos", "dividendos", "corretoras",
    "notificacoes", "mensagens", "arquivos", "documentos", "categorias", "configuracoes",
    "enderecos", "faturas", "cobrancas", "metas", "lancamentos", "movimentacoes",
]

# Only ever probed under a mangled name (see enumeration.leak_rpc_names), so a
# real function is never executed during discovery.
RPCS = [
    "get_user", "get_profile", "get_users", "is_admin", "handle_new_user", "get_balance",
    "get_portfolio", "get_transactions", "search", "get_stats", "get_dashboard",
    "create_user", "delete_user", "update_profile", "get_role", "has_role", "check_admin",
    "get_my_profile", "get_current_user", "increment", "get_summary", "calculate",
]


def load(path: Optional[str], default: list[str]) -> list[str]:
    """Load one name per line from path (blank lines and # comments ignored), else default."""
    if not path:
        return list(default)
    names = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.append(line)
    return names
