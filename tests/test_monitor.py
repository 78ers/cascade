from cascade.monitor import format_alert, decide_targets
from cascade.config import Config, ExitServer


def test_decide_targets_all_exits():
    cfg = Config(
        exit_servers=[
            ExitServer(id="fin", location="Фин", ip="1.1.1.1", relay_port=8444, vpn_port=8444),
            ExitServer(id="ger", location="Гер", ip="2.2.2.2", relay_port=8454, vpn_port=8454),
        ],
        mtproto_ports=[8443],
    )
    targets = decide_targets(cfg)
    # на каждый выход проверяем его ip:vpn_port (порт Xray на выходе); mtproto — на первом
    assert ("Фин VPN", "1.1.1.1", 8444) in targets
    assert ("Гер VPN", "2.2.2.2", 8454) in targets
    assert ("MTProto", "1.1.1.1", 8443) in targets


def test_format_alert():
    msg = format_alert([("Фин VPN", "1.1.1.1", 8444, False),
                        ("MTProto", "1.1.1.1", 8443, True)])
    assert "Фин VPN" in msg and "1.1.1.1:8444" in msg


def test_decide_targets_mtproto_per_exit():
    from cascade.monitor import decide_targets
    from cascade.config import Config, ExitServer
    cfg = Config(
        exit_servers=[ExitServer(id="ger", location="GER", ip="1.1.1.1", vpn_port=8444),
                      ExitServer(id="est", location="EST", ip="2.2.2.2", vpn_port=8454)],
        mtproto_ports=[8455],
        mtproto_port_exits={"8455": "est"},
    )
    mt = [t for t in decide_targets(cfg) if t[0] == "MTProto"]
    assert mt == [("MTProto", "2.2.2.2", 8455)]  # на EST (выход порта), не GER


def test_decide_targets_mtproto_legacy_first():
    from cascade.monitor import decide_targets
    from cascade.config import Config, ExitServer
    cfg = Config(
        exit_servers=[ExitServer(id="ger", location="GER", ip="1.1.1.1", vpn_port=8444),
                      ExitServer(id="est", location="EST", ip="2.2.2.2", vpn_port=8454)],
        mtproto_ports=[8443],  # незамаплен → exit_servers[0]
    )
    mt = [t for t in decide_targets(cfg) if t[0] == "MTProto"]
    assert mt == [("MTProto", "1.1.1.1", 8443)]
