set -euo pipefail
. /root/cascade-ph2/guard.sh
export DEBIAN_FRONTEND=noninteractive
dpkg-query -W -f='${Package}\n' | sort > /root/cascade-ph2/pkgs-before.txt
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; chmod 755 /usr/sbin/policy-rc.d   # демоны при установке не запускать
trap 'rm -f /usr/sbin/policy-rc.d' EXIT
nice -n 10 apt-get install -y --no-install-recommends nginx libnginx-mod-stream qrencode python3-venv git curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
nice -n 10 apt-get update -qq
nice -n 10 apt-get install -y --no-install-recommends caddy
systemctl disable nginx caddy >/dev/null 2>&1 || true   # до настройки не должны подниматься при перезагрузке
systemctl stop nginx caddy 2>/dev/null || true
rm -f /etc/nginx/sites-enabled/default
dpkg-query -W -f='${Package}\n' | sort > /root/cascade-ph2/pkgs-after.txt
comm -13 /root/cascade-ph2/pkgs-before.txt /root/cascade-ph2/pkgs-after.txt > /root/cascade-ph2/pkgs-added.txt
echo "добавлено пакетов: $(wc -l < /root/cascade-ph2/pkgs-added.txt)"
echo "--- проверка: слушающие порты:"; ss -tlnH | awk '{print $4}' | sort -u | tr '\n' ' '; echo
echo "--- служба: $(systemctl is-active ssh fail2ban | tr '\n' ' ')  msanalytics (таймеров активно): $(systemctl list-timers 'msanalytics-*' --no-legend | wc -l)"
echo "--- dpkg --audit: [$(dpkg --audit)]"; df -h / | awk 'NR==2{print "диск: свободно "$4}'; free -m | awk 'NR==2{print "память: доступно "$7" МБ"}'
