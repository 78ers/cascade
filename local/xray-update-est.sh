#!/usr/bin/env bash
# Обновление Xray на выходе EST (id TLN) до проверенной версии.
# Запуск на мосту под root: bash /root/xray-update-est.sh
# Порядок: скачать → сверить сумму → проверить конфиг НОВЫМ Xray (до замены) → сохранить старый →
# заменить и перезапустить → если Xray не поднялся, откат на старый сам. Ключи и порты не меняются.
set -u
EXIT_ID="TLN"
VER="v26.11.9"
SHA="b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82"   # SHA2-256 из Xray-linux-64.zip.dgst релиза

read -r EXIP EXUSER EXPORT < <(cd /opt/cascade && python3 -c 'from cascade.config import load_config,CONFIG_PATH;c=load_config(CONFIG_PATH);e=[x for x in c.exit_servers if x.id=="'"$EXIT_ID"'"][0];print(e.ip,e.ssh_user,e.ssh_port)')
if [ -z "${EXIP:-}" ]; then echo "ОШИБКА: выход $EXIT_ID не найден в конфиге"; exit 1; fi

ssh -p "$EXPORT" -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes \
    "$EXUSER@$EXIP" "bash -s -- $VER $SHA" <<'REMOTE'
set -u
VER="$1"; SHA="$2"
W=/root/xray-update; mkdir -p "$W"; cd "$W" || exit 1
URL="https://github.com/XTLS/Xray-core/releases/download/$VER/Xray-linux-64.zip"
echo "1) скачивание $VER"
curl -fsSL "$URL" -o xray.zip || wget -qO xray.zip "$URL" || { echo "ОШИБКА: не скачалось"; exit 1; }
echo "2) контрольная сумма"
echo "$SHA  xray.zip" | sha256sum -c - || { echo "ОШИБКА: сумма не совпала, ничего не заменено"; exit 1; }
echo "3) распаковка"
python3 -c "import zipfile;zipfile.ZipFile('xray.zip').extract('xray')" || { echo "ОШИБКА: распаковка"; exit 1; }
chmod 755 xray
./xray version | head -1
echo "4) проверка конфига новым Xray (боевой Xray не тронут)"
./xray run -test -config /usr/local/etc/xray/config.json || { echo "ОШИБКА: конфиг не принят, ничего не заменено"; exit 1; }
PORT=$(python3 -c "import json;print(json.load(open('/usr/local/etc/xray/config.json'))['inbounds'][0]['port'])")
echo "5) копия старого Xray: $W/xray.old"
cp -a /usr/local/bin/xray "$W/xray.old" || { echo "ОШИБКА: не удалось сохранить старый"; exit 1; }
echo "6) замена и перезапуск"
install -m 755 xray /usr/local/bin/xray.new && mv -f /usr/local/bin/xray.new /usr/local/bin/xray
systemctl restart xray; sleep 3
if systemctl is-active --quiet xray && ss -ltn "sport = :$PORT" | grep -q LISTEN; then
  echo "ГОТОВО"
  /usr/local/bin/xray version | head -1
  echo "служба: $(systemctl is-active xray)"
  ss -ltn "sport = :$PORT" | tail -1
  journalctl -u xray -n 4 --no-pager
else
  echo "ОШИБКА: Xray не поднялся — возвращаю старый"
  cp -a "$W/xray.old" /usr/local/bin/xray; systemctl restart xray; sleep 2
  echo "служба после отката: $(systemctl is-active xray)"
  exit 1
fi
REMOTE
