from cascade.panel.deploy import caddyfile, panel_unit, nginx_stream_conf


def test_caddyfile_has_domain_and_proxy():
    cf = caddyfile("tech.example.ru", 8088)
    assert "tech.example.ru" in cf
    assert "reverse_proxy 127.0.0.1:8088" in cf


def test_panel_unit_execstart():
    u = panel_unit("/usr/local/bin/cascade")
    assert "ExecStart=/usr/local/bin/cascade --panel" in u
    assert "[Install]" in u


def test_caddyfile_default_binds_to_domain():
    cf = caddyfile("example.com", 8088)
    assert cf.startswith("example.com {")
    # без порта — нет http-редиректа
    assert "redir" not in cf


def test_caddyfile_nginx_front_binds_to_port():
    cf = caddyfile("example.com", 8088, caddy_bind_port=8443)
    assert "example.com:8443 {" in cf
    assert "reverse_proxy 127.0.0.1:8088" in cf
    # добавлен http→https редирект на :443 (не на :8443)
    assert "http://example.com {" in cf
    assert "redir https://example.com" in cf
    assert ":8443" not in cf.split("redir https://example.com")[1].split("\n")[0]


def test_nginx_stream_conf_structure():
    conf = nginx_stream_conf("example.com", caddy_port=8443, telemt_port=8448)
    assert "load_module modules/ngx_stream_module.so;" in conf
    assert "stream {" in conf
    assert "ssl_preread on;" in conf
    assert "listen 443;" in conf
    assert "example.com  127.0.0.1:8443;" in conf
    assert "default         127.0.0.1:8448;" in conf
    assert "proxy_pass $cascade_backend;" in conf
    assert "limit_conn_zone" in conf
    assert "limit_conn cascade_addr 20;" in conf
    # нет http-блока
    assert "http {" not in conf


def test_nginx_stream_conf_custom_ports():
    conf = nginx_stream_conf("example.com", caddy_port=9000, telemt_port=9001)
    assert "127.0.0.1:9000" in conf
    assert "127.0.0.1:9001" in conf


def test_nginx_stream_conf_remote_telemt_host():
    conf = nginx_stream_conf("example.com", caddy_port=8443, telemt_port=8448, telemt_host="10.0.0.1")
    assert "default         10.0.0.1:8448;" in conf
    assert "127.0.0.1:8448" not in conf
    assert "127.0.0.1:8443;" in conf  # панель всегда на localhost


def test_panel_argv_builds_app(monkeypatch):
    import cascade.__main__ as m
    called = {}
    monkeypatch.setattr(m, "_serve_panel", lambda: called.setdefault("ok", True))
    monkeypatch.setattr("sys.argv", ["cascade", "--panel"])
    m.main()
    assert called.get("ok")
