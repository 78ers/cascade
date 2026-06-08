import subprocess

import pytest

from cascade.relay import valid_ip, dnat_rules, RelayRule, _ensure_zapret_rule, _NET_TUNING


def test_valid_ip():
    assert valid_ip("1.2.3.4")
    assert not valid_ip("999.1.1.1")
    assert not valid_ip("1.2.3.4; rm -rf /")
    assert not valid_ip("")


def test_dnat_rules_structure():
    rule = RelayRule(proto="tcp", in_port=8444, target_ip="1.2.3.4", out_port=8444)
    rules = dnat_rules(rule, iface="eth0")
    joined = [" ".join(r) for r in rules]
    assert any("PREROUTING" in r and "DNAT" in r and "1.2.3.4:8444" in r for r in joined)
    assert any("FORWARD" in r for r in joined)


def test_dnat_rejects_bad_ip():
    with pytest.raises(ValueError):
        RelayRule(proto="tcp", in_port=8444, target_ip="bad; ls", out_port=8444)


def test_net_tuning_includes_conntrack_liberal():
    assert "nf_conntrack_tcp_be_liberal=1" in _NET_TUNING


def test_ensure_zapret_rule_idempotent(monkeypatch):
    """Если правило уже есть (-C → 0), -A не вызывается."""
    calls = []

    def fake_run(args, **kwargs):
        calls.append(list(args))
        class R:
            returncode = 0
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    _ensure_zapret_rule("1.2.3.4", 8444)
    check_calls = [c for c in calls if "-C" in c]
    add_calls = [c for c in calls if "-A" in c and "NFQUEUE" in " ".join(c)]
    assert check_calls, "iptables -C должен вызываться"
    assert not add_calls, "iptables -A не должен вызываться если правило уже есть"


def test_ensure_zapret_rule_adds_if_missing(monkeypatch):
    """Если правила нет (-C → 1), -A добавляет его."""
    calls = []

    def fake_run(args, **kwargs):
        calls.append(list(args))
        class R:
            returncode = 1 if "-C" in args else 0
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    _ensure_zapret_rule("1.2.3.4", 8444)
    add_calls = [c for c in calls if "-A" in c and "NFQUEUE" in " ".join(c)]
    assert add_calls, "iptables -A должен вызываться если правила нет"
    # --queue-bypass обязателен (защита клиентов при падении nfqws)
    assert any("--queue-bypass" in " ".join(c) for c in add_calls)
    # FORWARD, не POSTROUTING
    assert any("FORWARD" in c for c in add_calls)
    # connbytes — только хендшейк
    assert any("connbytes" in " ".join(c) for c in add_calls)
