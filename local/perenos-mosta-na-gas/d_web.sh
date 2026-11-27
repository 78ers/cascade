set -euo pipefail
B=/root/cascade-ph2/bundle
. /root/cascade-ph2/guard.sh
PY="env PYTHONPATH=/opt/cascade /opt/cascade/.venv/bin/python"
install -m 600 $B/config.json /etc/cascade/config.json
install -m 600 $B/panel_secret /etc/cascade/panel_secret
(cd /opt/cascade && $PY -c "from cascade.config import load_config,CONFIG_PATH;c=load_config(CONFIG_PATH);print('конфиг: клиентов',len(c.clients),'выходов',len(c.exit_servers),'sub_direct у',sum(1 for k in c.clients if k.sub_direct))")
install -m 644 $B/nginx.conf /etc/nginx/nginx.conf
install -d -m 755 /etc/caddy/conf.d
install -m 644 $B/cascade-panel.caddy /etc/caddy/conf.d/cascade-panel.caddy
printf 'import /etc/caddy/conf.d/*.caddy\n' > /etc/caddy/Caddyfile
install -d -o caddy -g caddy -m 700 /var/lib/caddy/.local/share
tar -xzf $B/caddy-data.tgz -C /var/lib/caddy/.local/share/
chown -R caddy:caddy /var/lib/caddy/.local
echo "проверка настроек Caddy: $(caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1 | tail -1 | cut -c1-80)"
echo "проверка настроек nginx: $(nginx -t 2>&1 | tail -1)"
install -m 644 $B/cascade-panel.service /etc/systemd/system/cascade-panel.service
systemctl daemon-reload
systemctl enable --now cascade-panel; sleep 3
echo "панель: $(systemctl is-active cascade-panel), слушает: $(ss -tlnH | awk '{print $4}' | grep 8088 | tr '\n' ' ')"
curl -s --max-time 6 http://127.0.0.1:8088/robots.txt -o /dev/null -w 'панель /robots.txt → %{http_code}\n'
TOK=$(cd /opt/cascade && $PY -c "from cascade.config import load_config,CONFIG_PATH;c=load_config(CONFIG_PATH);print(next(k.sub_token for k in c.clients if k.name=='default'))")
curl -s --max-time 8 -D /root/cascade-ph2/h.txt -H 'User-Agent: Happ/1.0' http://127.0.0.1:8088/sub/$TOK -o /root/cascade-ph2/b.json -w 'подписка default → %{http_code}\n'
$PY -c "
import json
d=json.load(open('/root/cascade-ph2/b.json'))
v=d['outbounds'][0]['settings']['vnext'][0]
print('  профиль: хост', v['address'], 'порт', v['port'], '| правил', len(d['routing']['rules']), '| DNS', len(d['dns']['servers']))
"
grep -i -E "^(profile-update-interval|dns-from-json-enable)" /root/cascade-ph2/h.txt | tr -d '\r' | sed 's/^/  заголовок: /'
rm -f /root/cascade-ph2/h.txt /root/cascade-ph2/b.json
echo "caddy: $(systemctl is-active caddy || true) nginx: $(systemctl is-active nginx || true) — до переключения домена остановлены намеренно"
echo "порты: $(ss -tlnH | awk '{print $4}' | sort -u | tr '\n' ' ')"
echo "fail2ban: $(systemctl is-active fail2ban) | ssh: $(systemctl is-active ssh) | упавших служб аналитики: $(systemctl is-failed 'msanalytics-*' 2>/dev/null | grep -c failed || true)"
free -m | awk 'NR==2{print "память: доступно "$7" МБ"}'; df -h / | awk 'NR==2{print "диск: свободно "$4}'; uptime | sed 's/.*load/нагрузка:/'
