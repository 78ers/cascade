set -u
systemctl disable --now cascade-panel caddy nginx cascade-nat 2>/dev/null
iptables -t nat -F; iptables -t mangle -F FORWARD; iptables -F FORWARD; iptables -P FORWARD ACCEPT
rm -f /etc/systemd/system/cascade-panel.service /etc/systemd/system/cascade-nat.service /etc/sysctl.d/99-cascade-net.conf /etc/modules-load.d/cascade.conf
sysctl -w net.ipv4.ip_forward=0 >/dev/null
rm -rf /opt/cascade /etc/cascade /usr/local/bin/cascade /var/lib/caddy/.local/share/caddy
[ -s /root/cascade-ph2/pkgs-added.txt ] && DEBIAN_FRONTEND=noninteractive apt-get purge -y $(cat /root/cascade-ph2/pkgs-added.txt)
rm -f /etc/apt/sources.list.d/caddy-stable.list /usr/share/keyrings/caddy-stable-archive-keyring.gpg /usr/sbin/policy-rc.d
apt-get update -qq; systemctl daemon-reload
echo "порты: $(ss -tlnH | awk '{print $4}' | sort -u | tr '\n' ' ') | forward=$(sysctl -n net.ipv4.ip_forward) | nat-правил: $(iptables -t nat -S | grep -c -- '^-A')"
