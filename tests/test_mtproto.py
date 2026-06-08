from cascade.mtproto import (
    gen_secret, domain_from_secret, valid_secret, tg_link,
    _telemt_user_secret, _telemt_toml, _telemt_unit, _sanitize_toml_key,
    TELEMT_INTERNAL_PORT, TELEMT_BINARY, TELEMT_CFG_PATH,
)


def test_gen_secret_format():
    s = gen_secret("google.com")
    assert s.startswith("ee")
    assert valid_secret(s)
    assert domain_from_secret(s) == "google.com"


def test_domain_from_known_secret():
    s = "eea91f4200b5324624bcd3a9111cf746ea6c656e74612e7275"
    assert domain_from_secret(s) == "lenta.ru"


def test_valid_secret_rejects_bad():
    assert not valid_secret("xx123")
    assert not valid_secret("ee123")  # слишком короткий
    assert not valid_secret("ee" + "a" * 33)  # нечётная длина


def test_tg_link():
    link = tg_link("1.2.3.4", 8443, "eeABC")
    assert link == "tg://proxy?server=1.2.3.4&port=8443&secret=eeABC"


# --- TELEMT ---

def test_telemt_user_secret_extracts_32hex():
    ee = "ee" + "a" * 32 + "6c656e74612e7275"  # lenta.ru hex
    assert _telemt_user_secret(ee) == "a" * 32
    assert len(_telemt_user_secret(ee)) == 32


def test_telemt_user_secret_from_gen():
    ee = gen_secret("example.ru")
    user_sec = _telemt_user_secret(ee)
    assert len(user_sec) == 32
    assert all(c in "0123456789abcdef" for c in user_sec)


def test_sanitize_toml_key():
    assert _sanitize_toml_key("Alice Bot") == "Alice_Bot"
    assert _sanitize_toml_key("user@123") == "user_123"
    assert _sanitize_toml_key("valid-key_1") == "valid-key_1"
    assert _sanitize_toml_key("") == "user"
    assert len(_sanitize_toml_key("x" * 50)) == 32


def test_telemt_toml_structure():
    users = {"alice": gen_secret("example.ru"), "bob": gen_secret("test.ru")}
    toml = _telemt_toml("example.ru", users)
    assert f"port = {TELEMT_INTERNAL_PORT}" in toml
    assert 'tls_domain = "example.ru"' in toml
    assert "tls = true" in toml
    assert "classic = false" in toml
    assert "[access.users]" in toml
    assert "alice" in toml
    assert "bob" in toml
    # значения — 32-hex (без 'ee' и домена)
    alice_secret = _telemt_user_secret(users["alice"])
    assert f'alice = "{alice_secret}"' in toml


def test_telemt_toml_sanitizes_labels():
    users = {"Иван Иванов": gen_secret("test.ru")}
    toml = _telemt_toml("test.ru", users)
    assert "Иван Иванов" not in toml
    assert "[access.users]" in toml


def test_telemt_unit_content():
    unit = _telemt_unit()
    assert f"ExecStart={TELEMT_BINARY} {TELEMT_CFG_PATH}" in unit
    assert "Restart=always" in unit
    assert "LimitNOFILE=65536" in unit
    assert "[Install]" in unit
