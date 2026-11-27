set -euo pipefail
B=/root/cascade-ph2/bundle
. /root/cascade-ph2/guard.sh
PY="env PYTHONPATH=/opt/cascade /opt/cascade/.venv/bin/python"
install -m 600 $B/config.json /etc/cascade/config.json
install -m 600 $B/panel_secret /etc/cascade/panel_secret
install -m 644 $B/nginx.conf /etc/nginx/nginx.conf
install -m 644 $B/cascade-panel.caddy /etc/caddy/conf.d/cascade-panel.caddy
tar -xzf $B/caddy-data.tgz -C /var/lib/caddy/.local/share/
chown -R caddy:caddy /var/lib/caddy/.local
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1 | tail -1 | cut -c1-60
nginx -t 2>&1 | tail -1
systemctl restart cascade-panel; sleep 2
systemctl enable --now caddy; sleep 5
systemctl enable --now nginx; sleep 2
DOM=$(cd /opt/cascade && $PY -c "from cascade.config import load_config,CONFIG_PATH;print(load_config(CONFIG_PATH).domain)")
echo "службы: panel=$(systemctl is-active cascade-panel) caddy=$(systemctl is-active caddy) nginx=$(systemctl is-active nginx) cascade-nat=$(systemctl is-active cascade-nat)"
curl -sk --max-time 8 --resolve $DOM:443:127.0.0.1 https://$DOM/robots.txt -o /dev/null -w 'изнутри: через nginx :443 → %{http_code}\n'
curl -sk --max-time 8 --resolve $DOM:8443:127.0.0.1 https://$DOM:8443/robots.txt -o /dev/null -w 'изнутри: Caddy :8443 → %{http_code}\n'
curl -s --max-time 8 -H "Host: $DOM" http://127.0.0.1/ -o /dev/null -w 'изнутри: http :80 → %{http_code} (ожидается 308)\n'
echo -n "сертификат до: "; echo | openssl s_client -connect 127.0.0.1:443 -servername $DOM 2>/dev/null | openssl x509 -noout -enddate | cut -d= -f2
echo "журнал Caddy (ошибки за минуту): $(journalctl -u caddy --since '-2 min' --no-pager 2>/dev/null | grep -c -i -E 'error|fail' || true)"
echo "порты: $(ss -tlnH | awk '{print $4}' | sort -u | tr '\n' ' ')"
echo "fail2ban: $(systemctl is-active fail2ban) | ssh: $(systemctl is-active ssh) | упавших служб аналитики: $(systemctl is-failed 'msanalytics-*' 2>/dev/null | grep -c failed || true)"
free -m | awk 'NR==2{print "память: доступно "$7" МБ"}'; uptime | sed 's/.*load/нагрузка:/'
rm -f $B/caddy-data.tgz $B/cascade-panel.caddy $B/cascade-panel.service $B/config.json $B/nat.rules $B/nginx.conf $B/panel_secret; rmdir $B
echo "копия секретов в bundle удалена"
