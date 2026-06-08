#!/bin/bash
# CASCADE VPN — установщик. curl -sSf .../install.sh | bash
# Рекомендуемая ОС: Ubuntu 22.04 LTS (на выходах 24.04 сломан ssh.socket после ребута)
set -Eeuo pipefail

REPO="https://github.com/78ers/cascade.git"
DEST="/opt/cascade"
NFQWS_BIN="https://raw.githubusercontent.com/78ers/cascade/main/assets/nfqws-linux-amd64"

trap 'echo ""; echo "[ERROR] Установка упала на строке $LINENO"; echo "[ERROR] Команда: $BASH_COMMAND"; echo "Пришли это сообщение для диагностики."; exit 1' ERR

[ "$EUID" -eq 0 ] || { echo "[ERROR] Запустите от root: sudo bash install.sh"; exit 1; }

echo "[*] Установка зависимостей..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y python3 python3-pip python3-venv git qrencode \
    iptables-persistent netfilter-persistent curl \
    build-essential libnetfilter-queue-dev libnfnetlink-dev libmnl-dev libcap-dev

echo "[*] Установка nfqws (DPI-десинхронизация)..."
if command -v nfqws >/dev/null 2>&1; then
    echo "[*] nfqws уже установлен, пропускаем."
elif curl -fsSL "$NFQWS_BIN" -o /usr/sbin/nfqws 2>/dev/null; then
    chmod +x /usr/sbin/nfqws
    echo "[OK] nfqws скачан из репозитория."
else
    echo "[*] Бинарь недоступен, собираем из bol-van/zapret..."
    git clone --depth=1 https://github.com/bol-van/zapret /opt/zapret
    make -C /opt/zapret/nfq
    install -m755 /opt/zapret/nfq/nfqws /usr/sbin/nfqws
    echo "[OK] nfqws собран и установлен."
fi

echo "[*] Клонирование репозитория..."
if [ -d "$DEST/.git" ]; then
    git -C "$DEST" pull --ff-only
else
    rm -rf "$DEST"
    git clone --depth 1 "$REPO" "$DEST"
fi

echo "[*] Установка пакета..."
python3 -m venv "$DEST/.venv"
"$DEST/.venv/bin/pip" install --quiet --upgrade pip
"$DEST/.venv/bin/pip" install --quiet -e "$DEST"

# глобальная команда cascade
cat > /usr/local/bin/cascade <<EOF
#!/bin/bash
exec "$DEST/.venv/bin/python" -m cascade "\$@"
EOF
chmod +x /usr/local/bin/cascade

# Caddy (для веб-панели), если ещё нет
if ! command -v caddy >/dev/null 2>&1; then
    echo "[*] Установка Caddy (веб-панель)..."
    apt-get install -y debian-keyring debian-archive-keyring apt-transport-https gnupg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
        | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
        > /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -y && apt-get install -y caddy
fi

echo "[OK] Установлено. Запуск: cascade"
