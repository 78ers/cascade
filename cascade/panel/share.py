"""Share-токены: одноразовые ссылки на клиента с истечением.
Sub-токены: постоянные токены подписки Happ (/sub/<token>)."""
from __future__ import annotations

import datetime
import secrets

from cascade.config import ShareToken


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def gen_token() -> str:
    return secrets.token_urlsafe(32)


def gen_sub_token() -> str:
    """Постоянный токен подписки — короче share, но достаточно неугадываемый."""
    return secrets.token_urlsafe(16)


def find_by_sub_token(cfg, token: str):
    """Найти Client по sub_token. Возвращает Client или None."""
    if not token:
        return None
    for cl in cfg.clients:
        if cl.sub_token == token:
            return cl
    return None


def add_share(cfg, client_id: str, ttl_hours: int = 24) -> ShareToken:
    st = ShareToken(token=gen_token(), client_id=client_id,
                    created=_now().isoformat(), ttl_hours=ttl_hours)
    cfg.share_tokens.append(st)
    return st


def find_valid(cfg, token: str) -> "ShareToken | None":
    """Вернуть токен, если существует и не истёк, иначе None."""
    for st in cfg.share_tokens:
        if st.token != token:
            continue
        created = datetime.datetime.fromisoformat(st.created)
        if _now() < created + datetime.timedelta(hours=st.ttl_hours):
            return st
        return None  # найден, но истёк
    return None


def revoke(cfg, token: str) -> bool:
    """Удалить токен. True если был и удалён."""
    before = len(cfg.share_tokens)
    cfg.share_tokens = [st for st in cfg.share_tokens if st.token != token]
    return len(cfg.share_tokens) < before
