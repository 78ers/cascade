import datetime

from cascade.config import Config, Client
from cascade.panel.share import gen_token, add_share, find_valid, revoke, gen_sub_token, find_by_sub_token


def _cfg():
    return Config(clients=[Client(id="c1", name="phone", uuid="u-1")])


def test_gen_token_unguessable():
    t1, t2 = gen_token(), gen_token()
    assert t1 != t2
    assert len(t1) >= 32


def test_add_share_appends():
    cfg = _cfg()
    st = add_share(cfg, "c1", ttl_hours=24)
    assert st in cfg.share_tokens
    assert st.client_id == "c1"
    assert st.ttl_hours == 24


def test_find_valid_within_ttl():
    cfg = _cfg()
    st = add_share(cfg, "c1", ttl_hours=24)
    found = find_valid(cfg, st.token)
    assert found is not None and found.client_id == "c1"


def test_find_valid_expired():
    cfg = _cfg()
    st = add_share(cfg, "c1", ttl_hours=24)
    past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=25)
    st.created = past.isoformat()
    assert find_valid(cfg, st.token) is None


def test_find_valid_unknown_token():
    assert find_valid(_cfg(), "nope") is None


def test_revoke():
    cfg = _cfg()
    st = add_share(cfg, "c1")
    assert revoke(cfg, st.token) is True
    assert find_valid(cfg, st.token) is None
    assert revoke(cfg, st.token) is False


def test_gen_sub_token_unguessable():
    t1, t2 = gen_sub_token(), gen_sub_token()
    assert t1 != t2
    assert len(t1) >= 16


def test_find_by_sub_token_found():
    cfg = _cfg()
    cfg.clients[0].sub_token = "my-sub-token"
    cl = find_by_sub_token(cfg, "my-sub-token")
    assert cl is not None and cl.id == "c1"


def test_find_by_sub_token_not_found():
    assert find_by_sub_token(_cfg(), "nope") is None


def test_find_by_sub_token_empty():
    assert find_by_sub_token(_cfg(), "") is None
