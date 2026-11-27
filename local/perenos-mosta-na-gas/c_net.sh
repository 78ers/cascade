set -euo pipefail
B=/root/cascade-ph2/bundle
. /root/cascade-ph2/guard.sh
printf '%s\n' nf_conntrack iptable_nat xt_MASQUERADE xt_TCPMSS xt_conntrack tcp_bbr sch_fq > /etc/modules-load.d/cascade.conf
modprobe -a nf_conntrack iptable_nat xt_MASQUERADE xt_TCPMSS xt_conntrack tcp_bbr sch_fq
cat > /etc/sysctl.d/99-cascade-net.conf <<'X'
net.ipv4.ip_forward=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_mtu_probing=1
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.netfilter.nf_conntrack_tcp_be_liberal=1
X
install -d -m 700 /etc/cascade
install -m 600 $B/nat.rules /etc/cascade/nat.rules
cat > /etc/systemd/system/cascade-nat.service <<'X'
[Unit]
Description=CASCADE relay NAT rules
After=network-online.target systemd-modules-load.service
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/sbin/modprobe -a nf_conntrack iptable_nat xt_MASQUERADE xt_TCPMSS xt_conntrack
ExecStart=/bin/sh -c '/sbin/iptables-restore --noflush < /etc/cascade/nat.rules'
ExecStop=/bin/sh -c '/sbin/iptables -t nat -F; /sbin/iptables -t mangle -F FORWARD; /sbin/iptables -F FORWARD; /sbin/iptables -P FORWARD ACCEPT'
[Install]
WantedBy=multi-user.target
X
systemctl daemon-reload
sysctl -p /etc/sysctl.d/99-cascade-net.conf >/dev/null
systemctl enable --now cascade-nat.service
echo "--- правила после запуска:"; iptables -t nat -S | grep -c -- '-A PREROUTING.*DNAT' | sed 's/^/DNAT: /'; iptables -t nat -S POSTROUTING | grep -c MASQUERADE | sed 's/^/MASQUERADE: /'; iptables -S FORWARD | head -1; iptables -t mangle -S FORWARD | grep -c TCPMSS | sed 's/^/TCPMSS: /'
echo "--- проверка восстановления: остановить службу и запустить снова"
systemctl stop cascade-nat.service; echo "после stop: правил nat $(iptables -t nat -S | grep -c -- '^-A'), FORWARD: $(iptables -S FORWARD | head -1)"
systemctl start cascade-nat.service; echo "после start: DNAT $(iptables -t nat -S PREROUTING | grep -c DNAT), MASQUERADE $(iptables -t nat -S POSTROUTING | grep -c MASQUERADE), $(iptables -S FORWARD | head -1)"
echo "sysctl: forward=$(sysctl -n net.ipv4.ip_forward) cc=$(sysctl -n net.ipv4.tcp_congestion_control) qdisc=$(sysctl -n net.core.default_qdisc) liberal=$(sysctl -n net.netfilter.nf_conntrack_tcp_be_liberal)"
echo "fail2ban: $(systemctl is-active fail2ban) | ssh: $(systemctl is-active ssh) | порты: $(ss -tlnH | awk '{print $4}' | sort -u | tr '\n' ' ')"
