from cascade.hysteria import (
    gen_password, hysteria_server_yaml, hy2_url, valid_hy2_password,
)


def test_gen_password_nonempty_safe():
    pw = gen_password()
    assert pw and valid_hy2_password(pw)


def test_valid_hy2_password_rejects_injection():
    assert not valid_hy2_password("a b")        # пробел
    assert not valid_hy2_password("a\npassword")  # перевод строки
    assert not valid_hy2_password("")
    assert valid_hy2_password("Ab-9_z")


def test_server_yaml_has_listen_auth_obfs():
    y = hysteria_server_yaml(port=8444, auth_pw="AUTHPW", obfs_pw="OBFSPW",
                             mask_domain="www.bmw.de")
    assert "listen: :8444" in y
    assert "password: AUTHPW" in y          # auth
    assert "type: salamander" in y          # обфускация обязательна
    assert "password: OBFSPW" in y          # obfs-пароль
    assert "www.bmw.de" in y                # маска (cert CN + masquerade)


def test_hy2_url_format():
    url = hy2_url(host="5.5.5.5", port=8444, auth_pw="AUTHPW", obfs_pw="OBFSPW",
                  mask_domain="www.bmw.de", name="phone")
    assert url.startswith("hysteria2://AUTHPW@5.5.5.5:8444/")
    assert "obfs=salamander" in url
    assert "obfs-password=OBFSPW" in url
    assert "sni=www.bmw.de" in url
    assert "insecure=1" in url              # self-signed
    assert url.endswith("#phone")


def test_hy2_url_uses_bridge_host():
    # host в ссылке = IP моста (РФ), НЕ выхода — клиент бьёт в мост, мост DNAT'ит
    url = hy2_url(host="203.0.113.1", port=9000, auth_pw="A", obfs_pw="O",
                  mask_domain="m.example", name="x")
    assert "@203.0.113.1:9000" in url
