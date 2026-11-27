#!/usr/bin/env bash
# Копия настроек моста и выхода EST (id TLN) перед обновлением ядра и Xray.
# Запуск на мосту под root: bash /opt/cascade/local/backup-servers.sh
# Только читает серверы. Пишет один архив в /root (права 600). Адресов и ключей в скрипте нет.
set -u
EXIT_ID="TLN"
TS=$(date +%F-%H%M)
D="/root/cascade-backup-$TS"
umask 077
mkdir -p "$D/bridge" "$D/est" || exit 1

# --- мост: настройки, правила пересылки, службы ---
B="$D/bridge"
for p in /etc/cascade /etc/caddy /etc/nginx/nginx.conf /etc/iptables /etc/sysctl.d \
         /etc/modules-load.d /etc/cron.d /etc/ssh/sshd_config.d /etc/default/grub \
         /etc/netplan /etc/systemd/system/cascade-panel.service \
         /etc/systemd/system/cascade-zapret.service; do
  [ -e "$p" ] && cp -a --parents "$p" "$B/" 2>/dev/null
done
{
  echo "== uname";   uname -a
  echo "== uptime";  uptime -p
  echo "== kernels"; ls -l /boot/vmlinuz-*; dpkg -l 'linux-image*' | grep '^ii'
  echo "== cascade"; git -C /opt/cascade rev-parse HEAD
  echo "== mptcp";   sysctl net.mptcp.enabled
  echo "== units";   systemctl list-unit-files --state=enabled --no-pager
  echo "== crontab"; crontab -l
} > "$B/state.txt" 2>&1
iptables-save  > "$B/iptables-save.txt"  2>&1
ip6tables-save > "$B/ip6tables-save.txt" 2>&1

# --- выход EST: Xray, его конфиг и ключи, системные настройки ---
read -r EXIP EXUSER EXPORT < <(cd /opt/cascade && python3 -c 'from cascade.config import load_config,CONFIG_PATH;c=load_config(CONFIG_PATH);e=[x for x in c.exit_servers if x.id=="'"$EXIT_ID"'"][0];print(e.ip,e.ssh_user,e.ssh_port)')
if [ -z "${EXIP:-}" ]; then echo "ОШИБКА: выход $EXIT_ID не найден в конфиге"; exit 1; fi
SSHX=(ssh -n -p "$EXPORT" -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes "$EXUSER@$EXIP")
"${SSHX[@]}" 'tar czf - --ignore-failed-read /usr/local/etc/xray /usr/local/bin/xray /usr/local/share/xray \
  /etc/systemd/system/xray.service /etc/systemd/system/xray.service.d /etc/sysctl.d \
  /etc/modules-load.d /etc/ssh/sshd_config.d /etc/default/grub /etc/iptables /etc/netplan 2>/dev/null' \
  > "$D/est/est-files.tar.gz"
"${SSHX[@]}" 'uname -a; uptime -p; ls -l /boot/vmlinuz-*; dpkg -l "linux-image*" | grep "^ii"; \
  /usr/local/bin/xray version | head -1; sysctl net.mptcp.enabled; \
  systemctl list-unit-files --state=enabled --no-pager; iptables-save' > "$D/est/state.txt" 2>&1

# --- итог ---
[ -s "$D/est/est-files.tar.gz" ] || echo "ОШИБКА: копия выхода EST пустая"
tar czf "$D.tar.gz" -C /root "cascade-backup-$TS" && chmod 600 "$D.tar.gz"
echo
echo "Архив: $D.tar.gz"
ls -l "$D.tar.gz"
sha256sum "$D.tar.gz"
echo "Мост (первые файлы):";  tar tzf "$D.tar.gz" | grep '/bridge/' | head -8
echo "EST (содержимое):";      tar tzf "$D/est/est-files.tar.gz" | head -12
