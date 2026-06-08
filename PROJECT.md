# CASCADE VPN — описание проекта

Подробное описание для работы из новых сессий. Обновлено: 2026-06-08 (актуально).

> ⚠️ **БЕЗОПАСНОСТЬ РЕПО:** реальных IP/доменов/ASN/хостеров/провайдеров в репозитории быть НЕ должно (репо безопасен как будто публичный) — это деанон-палево. В доках — описательные плейсхолдеры (`<МОСТ_IP>`, `<ВЫХОД_IP>`, `example.com`), БЕЗ IP-образных строк, имён хостеров и ASN. В тестах — только синтетические фикстуры, не реальные диапазоны. Реальные значения живут ТОЛЬКО в `/etc/cascade/config.json` на сервере + в локальной памяти ИИ (не в репо).

> **Реализовано (планы 1+2):** мульти-выход (`exit_servers[]`/`clients[]`) + веб-панель целиком (Flask+Caddy, профили cascade/direct, share-страницы). Спека: [specs/2026-05-29-cascade-web-panel-design.md](docs/superpowers/specs/2026-05-29-cascade-web-panel-design.md). Планы: `plans/2026-05-29-multi-exit-backend.md`, `web-panel-{backend,app-core,features,deploy}.md`. Всё в main, **118/118 тестов**. Изменения 2026-06-05 (fingerprint, TG-в-каскад, переустановка GER) + подписка Happ — см. §12. Ресёрч обхода ТСПУ 2026 + планы — `docs/research/2026-06-06-dpi-bypass-tspu.md`, `docs/superpowers/plans/2026-06-06-*`. Проверка + сканирование SNI — `cascade/sni.py`, панель «Настройки→SNI» — см. §13.

> Краткие dev-заметки и pitfalls живут в [cascade/CLAUDE.md](cascade/CLAUDE.md) (автозагружаются ИИ). Этот файл — полная картина: архитектура, модули, потоки данных, статус, findings аудита.

---

## 1. Что это

Единый Python-CLI на **российском сервере**, который одной командой разворачивает и управляет всей системой обхода блокировок на **двух серверах**:

```
Клиент → РФ-сервер (мост, iptables DNAT) → Сервер выхода (Xray + mtg) → Интернет
```

- **РФ-сервер (мост):** «тупая труба». iptables DNAT перебрасывает пакеты в Финляндию, не расшифровывая. Здесь же крутится CLI `cascade`, cron-мониторинг и Telegram-уведомления.
- **Сервер выхода (напр. Финляндия):** Xray (VLESS+Reality, опц. XHTTP) + mtg (MTProto). Управляется по SSH с РФ-сервера.
- **Один конфиг:** `/etc/cascade/config.json` (серверы, креды VPN, настройки).

Заменяет ручную связку Amnezia + compmaniya + tgproxy единым меню. Референс по структурам — meridian (MIT), но его стек 3x-ui+Docker+nginx отброшен; взяты только `ssh.py` и структуры VLESS/Reality.

## 2. Топология и роли

| Узел | Что крутится | Как управляется |
|---|---|---|
| РФ-сервер (мост) | CLI, iptables DNAT relay (по правилу на выход), cron `cascade --monitor`, Telegram-бот, **веб-панель** (`cascade --panel` за Caddy) | локально (root) |
| Серверы выхода (N) | Xray (systemd `xray`), mtg на первом (`cascade-mtg@<port>.service`) | по SSH с РФ-сервера |
| Клиент (телефон/ПК) | Xray-клиент (Happ/OneXray/v2rayNG/Nekoray/NekoBox) | импорт профиля cascade/direct (см. §6) |

**Мульти-выход:** на мосту по DNAT-правилу на каждый выход (`relay_port` уникален → `exit.ip:vpn_port`). Клиент получает профиль на каждую локацию. **Веб-панель** (control-plane, НЕ в пути трафика) — админка в браузере по техдомену.

## 3. Раскладка репозитория

Репо: приватный `github.com/78ers/cascade`, ветка `main`. Исходники локально: `/Users/user/Desktop/CLAUDE/My-Cascade-VPN/`.

```
cascade/            # сам пакет (устанавливается в /opt/cascade)
  __main__.py       # точка входа, root-check, режим --monitor
  config.py         # dataclass Config → /etc/cascade/config.json
  console.py        # цветной вывод (лайм #CCFF00), QR, тема questionary
  menu.py           # TUI (questionary): 5 разделов
  wizard.py         # первичная установка (диалог + деплой на оба сервера)
  vpn.py            # деплой/рестарт Xray по SSH
  mtproto.py        # секреты mtg, ссылки, деплой по SSH
  relay.py          # iptables DNAT (локально на РФ-сервере)
  monitor.py        # cron-проверка + Telegram + авто-рестарт
  xray_config.py    # генерация серверного И клиентского config.json + VLESS-ссылки
  ssh.py            # SSH-коннектор (vendored из meridian, MIT)
  panel/            # веб-панель: app.py (Flask), auth (pbkdf2), share (токены), deploy (Caddy/systemd)
  CLAUDE.md         # dev-заметки/pitfalls
tests/              # юнит-тесты чистой логики (не SSH)
install.sh          # curl | bash установщик на РФ-сервер
README.md           # пользовательская дока
PROJECT.md          # этот файл
```

Рядом (в `.gitignore`, НЕ в репо): `meridian-main/`, `mtproto/`, `TelegramProxy-main/` — референсы.

## 4. Модули — справка

- **`__main__.py`** — `main()`. `--monitor` → `monitor.run_check` (cron). `--panel` → `_serve_panel()` (waitress отдаёт `panel.app.create_app` на 127.0.0.1). Иначе требует root и открывает `menu.main_menu`.
- **`config.py`** — dataclasses `ExitServer` (per-exit: `relay_port`/`vpn_port`/`vpn_sni`/`reality_*`), `Client` (`id/name/uuid/enabled/created`), `Panel` (`enabled/user/password_hash/port`), `ShareToken` (`token/client_id/created/ttl_hours`), `Config` (`exit_servers[]`/`clients[]`/`domain`/`panel`/`share_tokens[]`). `load_config` десериализует вложенные dataclasses + `_migrate` (старый single-exit → multi). `save_config` атомарно (tmp+`os.replace`, 0600).
- **`console.py`** — `info/ok/warn/err`, `qr()` (qrencode, тихо деградирует), `questionary_style()`, `err_console`.
- **`menu.py`** — `main_menu` (7: установка/VPN/MTProto/статус/настройки/**веб-панель**/выход). `vpn_menu`: клиенты (показать/добавить/удалить), профиль JSON, подменю **«Выходы»** (`exits_menu`: список/добавить-деплой/удалить). `_profile_screen` (клиент×выход×cascade|direct). `settings_menu`: Telegram/интервал/авто-рестарт/SSH/**домен**/**пароль панели**/reboot/удалить. `panel_menu` (включить панель: домен+пароль→`deploy.apply_panel`). SSH-операции в `try/except`→`_handle_error()`. Хелперы `_relay_ip`/`_conns`.
- **`wizard.py`** — `run_wizard()`: IP/SSH/название/SNI/домен → `ExitServer` как `exit_servers[0]` + первый `Client` → `vpn.deploy_vpn(conn, ex, clients)` → mtg → relay по `relay_port` → конфиг → ссылки. Весь деплой в `try/except`→traceback. `_get_local_ip()` (api.ipify.org, "" при сбое).
- **`vpn.py`** — `_run_checked`, `deploy_vpn(conn, exit, clients)` (генерит reality-ключи в exit, is-active+логи), `_rebuild_xray(conn, exit, clients)`, `add_vpn_client(cfg, name, conns)`/`remove_vpn_client(cfg, name, conns)` (синк uuid во ВСЕ выходы), `change_sni(conn, exit, cfg, sni)`, `print_vpn_links`/`client_vless_url`, `restart_vpn`.
- **`mtproto.py`** — `gen_secret/domain_from_secret/valid_secret/tg_link`; `deploy_mtproto()` (mtg с GitHub, проверки returncode+is-active), `restart_mtproto()`. mtg на первом выходе.
- **`relay.py`** — `RelayRule`, `dnat_rules()` (БЕЗ MASQUERADE), `_ensure_masquerade()` (общий, идемпотентно), `apply_rule/remove_rule` (на выход — по `relay_port`→`vpn_port`), `detect_iface`, `list_dnat`.
- **`monitor.py`** — `decide_targets/check_once` (4-кортежи `(label, ip, port, up)`, по каждому выходу `ip:vpn_port` + mtg на первом), `format_alert`, `send_telegram`, `run_check` (рестарт ТОЛЬКО упавших выходов).
- **`xray_config.py`** — `build_xray_config(clients: dict, ...)`, `build_client_xray_config()` (сплит+DNS), `client_profile_json/url(uuid, exit, relay_ip, direct=)` (cascade vs direct), `parse_x25519`, `vless_reality_url/xhttp_url`, gen uuid/short_id.
- **`ssh.py`** — `ServerConnection` (`run`/`write_file`/`check_ssh`), `tcp_connect`. Vendored meridian (MIT), мёртвый код удалён.
- **`panel/` (веб-панель):**
  - `app.py` — `create_app(config_path, secret_path)` Flask. Роуты: `/` decoy, `/boss` логин (CSRF), `/boss/` dashboard, `/boss/clients|exits|settings`, `/boss/logout`, публичная `/c/<токен>`. `login_required`, секрет сессии в `/etc/cascade/panel_secret`.
  - `auth.py` — `hash_password/verify_password` (pbkdf2_sha256, stdlib, `compare_digest`).
  - `share.py` — `gen_token/add_share/find_valid` (TTL)/`revoke`.
  - `deploy.py` — `caddyfile(domain, port)`/`panel_unit(bin)` (чистые) + `apply_panel` (пишет Caddyfile+systemd, поднимает; локально на мосту).

## 5. Потоки данных

**Установка (wizard):** ввод → SSH на сервер выхода → деплой Xray → деплой mtg → локально iptables DNAT для портов VPN/XHTTP/MTProto → сохранение конфига → ссылки+QR (host = IP РФ-сервера).

**Мониторинг (cron каждые N мин):** `cascade --monitor` → TCP-проба портов сервера выхода → при падении Telegram-алерт → (если `auto_restart`) рестарт Xray+mtg по SSH → повторная проба → итоговое уведомление.

**Клиентский профиль (§6):** меню VPN → собирает Xray client config.json из кредов в конфиге → печать + сохранение `/etc/cascade/client-config.json`.

## 6. Клиентский профиль: сплит-туннель (ключевая фича)

**Задача:** РФ-сайты идут с реального РФ IP устройства, иностранное (WhatsApp/Telegram/Instagram/YouTube) — через каскад в Финляндию.

**Почему только на клиенте:** туннель терминируется в Финляндии. Любой outbound на сервере выхода выходит с финского IP — серверный routing не даст РФ IP. Серверный split на мосту дал бы РФ datacenter-IP, но сломал бы «тупую трубу» (мост стал бы расшифровывать трафик в РФ-юрисдикции). Значит split — в клиенте, рядом с VLESS-профилем.

**Реализация:** `xray_config.build_client_xray_config(uuid, public_key, short_id, host, sni, vpn_port, ...)` → полный Xray client `config.json`:

- **inbounds:** socks `127.0.0.1:10808` + http `127.0.0.1:10809`.
- **outbounds:** `proxy` (VLESS+Reality на `host`=IP моста РФ) / `direct` (freedom) / `block` (blackhole).
- **routing** (`domainStrategy: IPIfNonMatch`):
  - `geosite:category-ru` → direct
  - `geoip:ru` + `geoip:private` → direct
  - остальное → proxy (→ мост → Финляндия)
- **dns** (split-DNS против leak):
  - РФ-домены (`geosite:category-ru`) → РФ-DNS Яндекс `77.88.8.8` (с `expectIPs: geoip:ru`)
  - прочее → Google DoH `https://dns.google/dns-query` внутри туннеля
  - `queryStrategy: UseIPv4`

`geoip`/`geosite` встроены в Xray-клиенты — не качаются (важно для РФ).

**Совместимость:** Happ, OneXray, v2rayNG, Nekoray, NekoBox (все Xray-core). **Karing отброшен** — на sing-box/Clash, тянет rule_set по URL github/jsdelivr (в РФ блокируется).

**Меню:** «Управление VPN» → «Профиль для клиента (JSON)» → печать + сохранение `/etc/cascade/client-config.json` (0600). QR для JSON не делается (большой) — QR только для vless-ссылки.

## 7. Схема конфига `/etc/cascade/config.json`

```
exit_servers: [                      # несколько серверов выхода
  { id, location, ip, ssh_user=root, ssh_port=22,
    relay_port=8444,                 # порт на РФ-мосту → DNAT на этот выход (уникален на мост)
    vpn_port=8444,                   # порт Xray на самом выходе (для direct-профиля и мониторинга)
    vpn_sni=www.google.com, vpn_xhttp_enabled, vpn_xhttp_port=8445, vpn_xhttp_path,
    reality_private_key, reality_public_key, reality_short_id }   # свои ключи на каждый выход
]
clients: [ { id, name, uuid, enabled=true, created, sub_token } ]   # один uuid на ВСЕ выходы; email в Xray = имя; sub_token = подписка Happ
vpn_name="CASCADE VPN"               # #fragment в ссылке, видно в клиенте
fingerprint="firefox"                # uTLS-отпечаток клиента (chrome/firefox/safari/…); chrome режет РФ-DPI, дефолт firefox
primary_exit_id=""                   # id выхода, который отдаёт подписка /sub (дефолт — exit_servers[0]); хелпер config.primary_exit()
mtproto_exit_id=""                   # id выхода по умолчанию для НОВЫХ mtg-портов (дефолт [0]); хелпер config.mtproto_exit()
mtproto_ports=[8443]                 # список mtg-портов
mtproto_port_exits={ "порт": exit_id }  # на каком выходе развёрнут mtg каждого порта; хелпер config.mtproto_port_exit(); незамаплен → [0]
monitor_interval_min=5, auto_restart=true
telegram_bot_token, telegram_chat_id
mtproto_secrets: { "порт": "секрет" }
mtproto_labels: { "порт": "имя юзера" }
domain: "tech.example.ru"            # техдомен веб-панели (план 2)
panel: { enabled, user="admin", password_hash, port=8088 }   # пароль задаётся в CLI/настройках
share_tokens: [ { token, client_id, created(ISO UTC), ttl_hours=24 } ]   # клиентские ссылки
```

Профили клиента: **cascade** (host=IP моста, port=relay_port) и **direct/admin** (host=IP выхода, port=vpn_port). Миграция старого single-exit конфига в `exit_servers[]`/`clients[]` — автоматом в `load_config._migrate`.

**Веб-панель (план 2, реализована):** `cascade/panel/` — `auth.py` (pbkdf2-хеш, stdlib), `share.py` (токены ссылок с TTL), `app.py` (Flask: `/` decoy, `/boss` логин+CSRF, `/boss/` dashboard, `/boss/clients|exits|settings`, публичная `/c/<токен>` с профилями+QR), `deploy.py` (Caddyfile/systemd генераторы + `apply_panel`). Запуск: `cascade --panel` (waitress 127.0.0.1:port) за Caddy (авто-TLS по домену). Включение: CLI пункт «Веб-панель» (домен+пароль → пишет конфиги, поднимает сервисы). Не проверено на живом мосту: ACME-сертификат, реальный Caddy/systemd.

## 8. Findings аудита (2026-05-28, повторный скан 2026-05-29)

Полный скан кода. **Критических багов нет**, чистая логика покрыта тестами. После повторного скана 2026-05-29 все находки закрыты или улучшены:

1. ~~**ssh.py — мёртвый код из вендора.**~~ ИСПРАВЛЕНО 2026-05-28: удалены `detect_local_mode`, `fetch_credentials`, `_copy_local_credentials`, `_copy_one_file`, module-level `scp_host`. Остались только `run`/`write_file`/`check_ssh`/`tcp_connect`.
2. ~~**ssh.py:295 — неверное имя продукта.**~~ ИСПРАВЛЕНО 2026-05-28: подсказка `meridian deploy ...` заменена на «Сменить SSH-юзера: меню Настройки → SSH-доступы».
3. ~~**config.py — хрупкость forward-compat.**~~ ИСПРАВЛЕНО 2026-05-28: `load_config` фильтрует неизвестные ключи, `vpn_uuid` мигрирует в `vpn_clients["default"]`.
4. ~~**relay.py — дублирование MASQUERADE.**~~ ИСПРАВЛЕНО 2026-05-29: MASQUERADE вынесен из `dnat_rules` в `_ensure_masquerade()` (идемпотентно через `iptables -C`), `apply_rule` добавляет его один раз на iface, `remove_rule` его не трогает (общая инфраструктура). Дубли и случайное снятие у других правил исключены.
5. ~~**`_get_local_ip()` → пустой IP при сбое curl.**~~ ИСПРАВЛЕНО 2026-05-29: `wizard._get_local_ip()` возвращает "" + warn; в `menu.py` добавлен `_relay_ip(st)` (спрашивает IP вручную при сбое), генерация профиля отменяется при пустом IP. Все точки меню используют `_relay_ip`.
6. **mtproto.py deploy — зависит от GitHub API.** УЛУЧШЕНО 2026-05-29: добавлена проверка пустого `TAG`, returncode установки/запуска + `systemctl is-active` с логами при провале (как в vpn.py). Остаётся зависимость от доступности `api.github.com` и релизов 9seconds/mtg. Server-side, не тестировалось.
7. **Сетевой тюнинг ядра отсутствовал — контент вставал.** ИСПРАВЛЕНО 2026-06-02 (коммит ab96053): транспорт каскада = VLESS+Reality поверх raw TCP (TCP-в-TCP), дефолты ядра (cubic+pfifo_fast+mtu_probing=0) на дальнем канале мост→выход давали стопы. Добавлены: `relay._ensure_net_tuning()`+`_ensure_mss_clamp()` (мост, в `apply_rule`), `vpn._tune_exit()` (выход, в `deploy_vpn`) — BBR+fq+mtu_probing=1+буферы 16M+MSS clamp. Проверено на живом проде: лосс ~0.004% на 110k пакетов, MTU клиента 1340 (норма). BBR — страховка на час-пик РФ-транзита. Заодно `vpn._install_xray` убирает `User=nobody` из xray.service (спам systemd).

## 9. Статус и что НЕ проверено на живом сервере

Код полный, **118/118 юнит-тестов зелёные** (`python3 -m pytest tests/`). Реализовано и влито в main: план 1 (мульти-выход бэкенд) + план 2 (веб-панель целиком: 2a config/auth/share, 2b-1 ядро Flask, 2b-2 фич-роуты, 2b-3 деплой) + подписка Happ (`/sub/<token>`, см. §12) + проверка и сканирование SNI (`cascade/sni.py`, панель «Настройки→SNI», см. §13). НЕ проверено с реальным SSH+root (задача следующих сессий):

- `vpn.deploy_vpn` (новый выход), `add_vpn_client`/`remove_vpn_client` (синк по нескольким выходам), `change_sni`.
- `mtproto.deploy_mtproto`, `relay.apply_rule` с разными `relay_port` на одном мосту.
- Формат вывода `xray x25519` текущей версии (парсер 2 формата — свериться).
- **Клиентский профиль на устройстве:** импорт в Happ/v2rayNG, РФ-сайт → РФ IP (2ip.ru), иностранное → выход; direct-профиль (минуя мост). DoH `dns.google` — проверить bootstrap-резолв; при зацикливании → `https://8.8.8.8/dns-query`.
- **Веб-панель на живом мосту:** `cascade --panel` + Caddy: выдача ACME-сертификата (нужны открытые 80/443 + A-запись домена на мост), `/` → decoy, `/boss` логин, `/c/<токен>` → профили+QR. Caddy `reverse_proxy` без rate_limit (стандартный Caddy) — анти-брут `/boss` через fail2ban опционально.

## 10. Разработка

```bash
python3 -m pytest tests/        # только наши тесты (НЕ голый pytest — подхватит meridian-main/tests)
python3 -m py_compile cascade/*.py
```

- Установка на сервер: `curl -sSf https://raw.githubusercontent.com/78ers/cascade/main/install.sh | bash` → venv в `/opt/cascade`, команда `/usr/local/bin/cascade`.
- Pitfalls (детали в cascade/CLAUDE.md): XHTTP `flow=""`, `shlex.quote` на всех интерполяциях в `conn.run()`, host в VLESS-ссылке = IP РФ-сервера, секрет mtg чётной длины.
- Git: токен 78ers в macOS keychain, `git push` работает без явного токена. Коммиты — conventional на русском.
- Интерфейс: русский, лайм (#CCFF00) на чёрном, questionary.

---

## 11. Обработка ошибок и диагностика

### install.sh
`trap 'echo "[ERROR] строка $LINENO: $BASH_COMMAND"' ERR` — при любой ошибке shell выводит номер строки и команду. Пользователь видит что именно упало.

### vpn.py — `_run_checked(conn, cmd, desc, timeout)`
```python
def _run_checked(conn, cmd, desc, timeout=30):
    info(desc)
    r = conn.run(cmd, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"{desc} — ошибка (код {r.returncode}):\n{r.stderr or r.stdout}")
    return r.stdout
```
Все критические SSH-команды в `deploy_vpn` и `_rebuild_xray` проходят через `_run_checked`. После деплоя Xray дополнительно проверяется `systemctl is-active xray` — при провале собираются логи (`journalctl -u xray -n 20`) и поднимается `RuntimeError` с полным текстом.

### wizard.py — try/except на весь деплой
```python
try:
    conn.check_ssh()
    vpn.deploy_vpn(conn, cfg)
    ...
except SSHError as e:
    err(f"Ошибка SSH: {e}")
    if e.hint: err(f"Подсказка: {e.hint}")
    _print_report_hint()
except RuntimeError as e:
    err(str(e))
    _print_report_hint()
except Exception:
    traceback.print_exc()
    _print_report_hint()
```
`_print_report_hint()` печатает:
```
──────────────────────────────────────────
Скопируй сообщение выше и пришли для диагностики.
──────────────────────────────────────────
```

### menu.py — `_handle_error(e)`
SSH-операции в `vpn_menu` (добавить клиента, удалить, сменить SNI) обёрнуты в `try/except Exception → _handle_error(e)`. Та же подсказка «пришли это».

### Прогресс-сообщения при деплое
```
[*] Проверка SSH-соединения с <ip>...
[*] Установка Xray на сервере выхода (~2 мин)...
[*] Генерация Reality-ключей
[*] Открытие порта 8444...
[*] Включение Xray в автозапуск
[*] Заливка config.json на сервер выхода...
[*] Перезапуск Xray
[OK] Xray развёрнут и работает
```

---

## 12. Изменения 2026-06-05

**Fingerprint uTLS (новая фича).** `Config.fingerprint` (глобальный, дефолт **firefox** — chrome режет РФ-DPI), список `xray_config.FINGERPRINTS` (chrome/firefox/safari/ios/android/edge/360/qq/random/randomized). Только клиентский (серверный inbound его не эмитит) → смена = перегенерация профилей, без SSH. Пробрасывается в `client_profile_json` (`realitySettings.fingerprint`) и `client_profile_url` (`&fp=`). UI: CLI «Настройки → Фингерпринт», панель «Настройки → select». Клиентам после смены — переимпорт профиля.

**Telegram через каскад (MTProto в РФ мёртв).** ТСПУ с 01.04.2026 блочит MTProto Fake-TLS по JA3/JA4 ClientHello. mtg 2.2.8 + свежее приложение Telegram — всё равно блок (у mtg нет ротации fp). Решение: убраны правила `domain:t.me→proxy`/`geosite:telegram→direct` из `build_client_xray_config` → Telegram (не-РФ домены+IP) идёт в catch-all→proxy (каскад, Reality/firefox-fp). MTProto в клиенте отключается; mtg оставлен (8443/45/46+8447) idle на случай смены ситуации. **Не предлагать standalone MTProto в РФ.**

**Переустановка выхода GER.** GER переустановлен на **Ubuntu 22.04** (24.04 `ssh.socket` не переживал ребут → sshd рвал kex → SSH к выходу умирал). sshd слушает 22+2222 (`/etc/ssh/sshd_config.d/cascade-port.conf`); мост ходит на **2222** (провайдер RU-провайдер режет 22 с IP моста — RST). Передеплой с моста переиспользует reality-ключи+mtproto-секреты из конфига → **клиентские ссылки (VLESS+MTProto) выжили**. Перед переустановкой — бэкап `/etc/cascade/config.json` (источник правды, секреты/ключи).

**Фриз ленты решён переустановкой — был битый инстанс, НЕ маршрут.** iperf3 GER→мост = ~90 Мбит (было 1-2). Прошлый диагноз «битый маршрут RU-провайдер→РФ» неверен. Ёмкость: CPU/RAM 2/2 не лимит; по ~90 Мбит ~15-20 активных видео / ~50-80 смешанных юзеров.

**Панель.** `_ensure_host_key(ip,port)` авто-добавляет host-key выхода перед `check_ssh` (нет TTY в вебе) — фикс «Проверить SSH+TCP». waitress: 8 потоков + логгер `waitress.queue`→ERROR (убран спам «Task queue depth»). Диагностика: одна кнопка **«Тест скорости» (iperf3 мост↔выход)** + «Полная диагностика» (speed+ss+ping+exit_speed), убраны T1-T4.

**Подписка Happ — доделана и влита (104/104).** Один URL на клиента вместо ручной рассылки JSON; Happ обновляет при открытии → смена fp/ключей/роутинга прилетает сама. `Client.sub_token` (стабильный, `secrets.token_urlsafe`), роут `GET /sub/<token>` в `panel/app.py` (валидный → `client_profile_json` по первому выходу/cascade; невалидный → decoy), `share.gen_sub_token`/`find_by_sub_token`, кнопка «📡 Подписка» + сброс токена в `clients.html`. Ссылки подписки/share с `https://` (Flask за Caddy). План: `docs/superpowers/plans/2026-06-05-happ-subscription.md`. **Остаётся (на устройстве, не код):** Шаг 0 плана — проверить wire-формат подписки в Happ на реальном телефоне (raw JSON vs base64 vs заголовки); импорт и применение split-роутинга.

---

## 13. Изменения 2026-06-06 (SNI-инструменты + NLM-ресёрч)

**NotebookLM RAG.** Создан блокнот «CASCADE VPN — DPI bypass research 2026» (id `83c363ec`). Добавлено 38+ источников: meridian, naiveproxy, mtg, comp_maniya, Xray-core, RealiTLScanner, tg-ws-proxy, dpi-checkers, roscomvpn-routing, iplist.opencck, antizapret-sing-box, censorcheck, rkn-block-checker, v2rayN, hiddify, Happ, форумы, YouTube. Используется как RAG: `$NLM ask "вопрос"` вместо чтения исходников. Ресёрч-отчёт: `docs/research/2026-06-06-dpi-bypass-tspu.md`.

**Проверка SNI-кандидата (`cascade/sni.py` + панель «Настройки→SNI»).**
- `valid_domain(d)` — regex-валидация, антиинъекция.
- `build_check_cmd(domain)` — openssl + curl команда для SSH на выход; `shlex.quote` на домен.
- `parse_check(output, domain)` — разбор: TLS1.3/X25519/h2/HTTP-код/редирект. Кросс-доменный редирект дисквалифицирует; **path-redirect (тот же хост, напр. bmw.de→bmw.de/de/) НЕ дисквалифицирует** — Reality перехватывает на TLS-уровне.
- Пресеты немецких доменов (гео-правдоподобны для GER-выхода): `www.bmw.de`, `www.siemens.com`, `www.sap.com`, `www.telekom.de`, `www.spiegel.de`, `www.zalando.de`.
- Панель: роут `/boss/sni-check` (GET+POST), форма + кнопки-пресеты, таблица результатов по каждому выходу.

**Сканирование подсети (`build_scan_cmd` + `/boss/sni-scan`).**
- Инструмент: `XTLS/RealiTLScanner` — сканирует подсеть провайдера (`-addr <exit_ip>`), находит соседей с TLS1.3+X25519+h2. CSV-вывод (`IP,ORIGIN,CERT_DOMAIN,...`).
- `build_scan_cmd(ip, threads=16, timeout_s=3)` — скачивает бинарник если нет (`wget` с GitHub), запускает (`~45 сек на /24`), читает CSV.
- `parse_scan_csv(output)` — извлекает уникальные домены, убирает `*.` wildcard-префиксы.
- Панель: кнопка «🔍 Сканировать подсеть» → SSH на первый выход → список кандидатов; каждый домен — кнопка для немедленной проверки.
- **Root не нужен.** Запуск с выхода (а не мака) — нужен GER-ASN, не маки-ASN.

**Коммиты сессии:**
- `d94b6c0` — docs: ресёрч ТСПУ 2026 + планы
- `8f77e0b` — feat(panel): проверка SNI-кандидата
- `b67a938` — fix(sni): path-redirect не дисквалифицирует
- `bf3808c` — feat(sni): сканирование подсети через RealiTLScanner

**Деплой (ожидает):** `git pull && systemctl restart cascade-panel` на мосту (<МОСТ_IP>). Перед ребутом мост: `netfilter-persistent save`.

## 14. Изменения 2026-06-06 (SNI-харднинг + zero-downtime + CLI-паритет)

**Тестов: 122/122.**

**SNI-харднинг (продолжение §13).**
- `parse_scan_csv` теперь читает индекс `CERT_DOMAIN` из заголовка CSV (реальный формат v0.2.3 имеет 11 колонок, CERT_DOMAIN на индексе 8, не 2 как предполагалось).
- `_good_sni_candidate(domain)` — фильтрует `.ru/.ua/.by/.kz` TLD и ключевые слова (`vpn`, `yandex`, `vk.com`, `tinkoff` и т.д.) из результатов сканера.
- Сканер переключён с `wget` на `curl` (надёжнее на свежих серверах).
- SNI сменён с `www.google.com` на `yahoo.com` на продакшн GER-выходе (подтверждено живым трафиком).

**Zero-downtime SNI-ротация.**
- `ExitServer.vpn_sni_legacy: list` — при смене SNI старый уходит в legacy, Xray принимает оба.
- `ExitServer.vpn_sni_changed_at: str` — ISO-дата смены, отображается в панели рядом с кнопкой «очистить».
- `vpn.change_sni()` → пушит старый SNI в legacy + фиксирует дату. `vpn.sni_legacy_clear()` → убирает legacy.
- Панель (Выходы): показывает `⚠ legacy: google.com · сменён 2026-06-06 (безопасно очищать через 48ч)` + кнопка «очистить» с confirm-диалогом.
- Принцип зафиксирован в `cascade/CLAUDE.md` §«zero-downtime при изменении серверных параметров».

**Подписка (sub): формат уточнён.**
- Подтверждено: Happ работает с raw JSON (полный Xray-конфиг с routing/split-tunnel). base64 URL-список тоже стандартен, но не протестирован на реальном Happ — отложен до появления второго выхода.
- Текущий `/sub/<token>` возвращает JSON первого выхода (без изменений).

**CLI-паритет (аварийный режим).**
- `vpn_menu`: +включить/выключить клиента, +переименовать, +URL подписки с QR, +SNI-проверка домена.
- `exits_menu`: +сменить SNI (с legacy), +перезапустить Xray, +проверить SSH+TCP.
- `mtproto_menu`: переписан в loop, +добавить порт, +сменить секрет, +удалить порт (было только показ+рестарт).

**Коммиты сессии (продолжение):**
- `0cf9c42` — fix: parse_scan_csv читает CERT_DOMAIN из заголовка
- `2c4803b` — sni: фильтр плохих кандидатов из сканера
- `5bed007` — feat: zero-downtime SNI-ротация (vpn_sni_legacy)
- `e83e439` — feat: дата смены SNI рядом с кнопкой очистки
- `bd993f2` — fix: curl вместо wget для загрузки RealiTLScanner
- `4fe0f37` — feat(cli): sync CLI с панелью (toggle/rename/sub/SNI/MTProto CRUD)

---

## 15. Изменения 2026-06-07 (zapret DPI-десинхронизация + conntrack liberal)

**Тестов: 127/127.**

**Мотивация.** ТСПУ 2026 — статистический анализ трафика + RST-инжекция. Reality+firefox закрывает TLS-отпечаток, но не пакетный уровень. NLM-ресёрч (38+ источников, 15 вопросов) подтвердил: zapret/nfqws на РФ-мосту — стандартный ответ на пакетный DPI.

**1. zapret/nfqws DPI-десинхронизация (`relay.py`).**
- `_install_nfqws()` — `apt-get install nfqws` (нет в Ubuntu repo) → fallback: `git clone bol-van/zapret + make`. Зависимость `libcap-dev` нужна для сборки.
- `_ensure_zapret_service()` — systemd-юнит `cascade-zapret`: `nfqws --qnum=200 --dpi-desync-any-protocol --dpi-desync=fake,multisplit --dpi-desync-ttl=5`, `Restart=always RestartSec=3`.
- `_ensure_zapret_rule()` — iptables `mangle FORWARD` (не POSTROUTING — DNAT-транзит в iptables идёт через FORWARD), `connbytes 0:6` (только первые 6 пакетов = TLS-хендшейк, data-stream без нагрузки), `mark 0x40000000` (анти-петля), `--queue-bypass` (при падении nfqws ядро ACCEPT, клиенты не теряют связь).
- `_ensure_zapret()` — оркестратор: `which nfqws` → install → service → rule.
- Добавлен вызов в `apply_rule()` после `_ensure_net_tuning()`.
- **Отказоустойчивость:** `--queue-bypass` + `Restart=always` → клиенты не замечают падения nfqws.

**2. `nf_conntrack_tcp_be_liberal=1` (`relay.py → _NET_TUNING`).**
- ТСПУ инжектирует RST с неверным ACK-номером → conntrack без этого флага помечает пакет INVALID → nfqws не перехватывает → RST рвёт соединение. Флаг делает conntrack терпимым к bad-ACK RST → nfqws перехватывает → десинхронизирует. Это была критическая недостача прошлого тюнинга.

**3. MSS clamp `--set-mss 1340` (вместо `--clamp-mss-to-pmtu`).**
- Фиксированное значение = стабильный MSS для TCP-in-TCP; PMTU-clamp непредсказуем при вложенных туннелях.

**4. Убран sniffing с серверного inbound (`xray_config.py`).**
- Выход — «тупая труба» без routing rules → sniffing не используется, только жрёт CPU. Убрано из `_reality_inbound()`.

**Деплой на живое:**
- Мост <МОСТ_IP>: `git pull && systemctl restart cascade-panel && apply_rule()` — выполнено.
- nfqws собран из исходников (нужен `libcap-dev` сверх стандартного build-essential).
- `cascade-zapret`: active. NFQUEUE FORWARD: настроен. `nf_conntrack_tcp_be_liberal`: 1.
- GER <ВЫХОД1_IP>: `_rebuild_xray` выполнен с моста — sniffing убран, Xray перезапущен.

**Коммит:** `471c596` — Add zapret DPI desync, conntrack liberal mode, fix MSS clamp, remove server sniffing.

---

## 16. Изменения 2026-06-07 (TELEMT bridge MTProto + nginx L4 SNI-роутинг)

**Тестов: 137/137.** Коммиты: `28506a9`, `72debd3`.

**Мотивация.** Standalone MTProto (mtg) мёртв с 01.04.2026 — ТСПУ режет Fake-TLS по JA3/JA4 ClientHello. TELEMT (Rust, `telemt/telemt`) даёт probe-resistance + domain fronting: без правильного секрета отдаёт реальный сайт → не попадает в серый список. Размещение на мосту (AS-XXXXXX RU) — лучший ASN для мягкой инспекции. Субдомен `test.example.com` → нейтральное имя.

**Архитектура.**
- nginx stream (L4 TLS-passthrough) на :443, SNI-роутинг:
  - SNI = `example.com` → Caddy :8443 (панель)
  - SNI = всё остальное (маска из ee-секрета) → TELEMT :8448
- Caddy переходит с :443 на :8443; авто-TLS работает (SNI `example.com` достигает Caddy через passthrough; ACME HTTP-01 на :80 не затронут).
- Клиент подключается к `test.example.com:443` (DNS A → <МОСТ_IP> вручную); TLS SNI = маска-домен из ee-секрета → nginx роутит в TELEMT.
- TG proxy link: `tg://proxy?server=test.example.com&port=443&secret=ee...`

**Что изменилось в коде.**

`cascade/mtproto.py`:
- `TELEMT_INTERNAL_PORT=8448`, `TELEMT_CFG_PATH`, `TELEMT_UNIT_NAME=cascade-telemt`
- `_telemt_user_secret(ee_secret)` → `ee_secret[2:34]` (32 hex для TELEMT `access.users`)
- `_telemt_toml(mask_domain, users)` — TOML-конфиг: `[censorship] tls_domain`, `[access.users]`, порт 8448, `mask=true`, `tls_emulation=true`
- `_telemt_unit()` — systemd unit `cascade-telemt` (`ExecStart=/usr/local/bin/telemt /etc/cascade/telemt.toml`)
- `_install_telemt_local()` — скачать `telemt/telemt` latest release (GitHub API, GNU/musl)
- `deploy_telemt_local(mask_domain, users)` — записать TOML + юнит + systemctl enable/restart
- `restart_telemt_local()`, `remove_telemt_local()`
- Старые SSH-функции (deploy_mtproto, restart_mtproto, remove_mtproto) — **не тронуты**

`cascade/panel/deploy.py`:
- `caddyfile(domain, port, caddy_bind_port=443)` — при `caddy_bind_port=8443` биндинг `domain:8443` + http→https редирект на :443
- `nginx_stream_conf(panel_domain, caddy_port=8443, telemt_port=8448)` — полный `/etc/nginx/nginx.conf` (только stream-блок; `limit_conn 20` по IP; `proxy_connect_timeout 10s`)
- `apply_nginx_stream(panel_domain, caddy_port, telemt_port)` — apt nginx + write + nginx -t + reload
- `apply_panel(domain, port, cascade_bin, use_nginx_stream=False)` — при `True`: Caddy :8443 + `apply_nginx_stream()`

`cascade/config.py`:
- `Config.bridge_mtproto_secrets: dict` — `{label: ee_secret}` (один TELEMT-инстанс, несколько юзеров)
- `Config.bridge_mtproto_domain: str` — маска TLS (tls_domain в TELEMT TOML)
- `TELEMT_BRIDGE_PORT=8448` — учитывается в `used_ports()` при наличии bridge MTProto

`cascade/panel/app.py`:
- `_bridge_mtproto_items(c)` → TG-ссылки с `server=test.{domain}&port=443`
- `POST /boss/bridge-mtproto/add` — валидация label + valid_domain(mask_domain), `deploy_telemt_local`, сохранить конфиг
- `POST /boss/bridge-mtproto/<label>/remove` — удалить из dict, редеплоить если остались юзеры / `remove_telemt_local()` если пусто
- `POST /boss/bridge-mtproto/restart` — `restart_telemt_local()`

`cascade/panel/templates/clients.html`:
- Новая секция «Bridge MTProto (TELEMT)» с формой (label + mask_domain из SNI-сканера), QR, копировать, удалить, restart
- Старая секция переименована в «MTProto (exit server, idle)»

**Защита от роботов/сканеров.**
- nginx stream: `limit_conn 20` — не более 20 TCP-соединений с одного IP одновременно
- Caddy: блокировка сканеров по User-Agent (sqlmap/nikto/zgrab/поисковики) — без изменений
- TELEMT probe-resistance: неправильный коннект → реальный сайт (не детектируется как прокси)
- Субдомен `test.example.com` (нейтральное название, не раскрывает Telegram)

**✅ Задеплоено 2026-06-07:**
1. DNS: `test.example.com → <МОСТ_IP>` — добавлена A-запись в RU-хостер DNS.
2. SNI-скан моста: `/usr/local/bin/realitls_scanner -addr <МОСТ_IP>/24` → выбран `example.org` (AS-XXXXXX, TLS1.3+h2+X25519, Let's Encrypt).
3. Панель → Клиенты → Bridge MTProto → добавлен `tg1 / example.org`. `cascade-telemt` active на :8448.
4. `apply_panel(use_nginx_stream=True)` — nginx установлен + `libnginx-mod-stream`, конфиг с `load_module modules/ngx_stream_module.so;` записан.
5. Порты: `:443` nginx, `:8443` Caddy, `:8448` TELEMT — все active.
6. **❌ TG-прокси с РФ-устройства не заработал** — причина не установлена.

**🔴 Открыто — диагностика TELEMT:**
- Проверить probe-resistance: `curl -sv https://test.example.com/` с внешней машины → должен ответить example.org (probe отдаёт маску)
- Проверить TELEMT логи: `journalctl -u cascade-telemt -n 50`
- Проверить формат TG-ссылки: `tg://proxy?server=test.example.com&port=443&secret=ee<hex>` — secret должен начинаться с `ee` и содержать маску `example.org` в hex
- Возможная причина: ТСПУ режет по JA3/ClientHello даже TELEMT (rustls fingerprint) — у нас нет данных по rustls JA4 в российском контексте
- Возможная причина: TELEMT не может достучаться до example.org как маски (NAT/firewall на мосту?)
- Возможная причина: DNS для test.example.com не propagated на устройстве в момент теста

**Примечание (nginx stream):** стандартный `nginx` на Ubuntu 24.04 не грузит stream-модуль автоматически. Фикс: `load_module modules/ngx_stream_module.so;` в nginx.conf + `libnginx-mod-stream` пакет (коммит `93b2e67`).

## 17. Изменения 2026-06-08 (основной выход + подписка с выбором + MTProto per-port)

**Контекст:** добавлен второй выход EST (`id=TLN`, <ВЫХОД2_IP>, ~48 Мбит через Reality). GER (<ВЫХОД1_IP>) деградировал по пирингу до ~3 Мбит. Диагностика скорости: raw-iperf3 мост↔выход — **невалидная метрика** (ТСПУ DPI душит голый TCP: EST raw=0 байт, но через Reality 48 Мбит). Реальную скорость даёт только fast.com через каскад. См. память `project_cascade_speedtest_metric`.

**Основной выход (primary) — подписка:**
- `Config.primary_exit_id` + `config.primary_exit(cfg)` (id или [0], None если нет выходов).
- `/sub/<token>` отдаёт **основной** выход (не жёстко [0]); интервал авто-обновления **24→3ч** (`profile-update-interval`).
- Подписка с выбором сервера: `/sub/<token>?exit=<eid>` — вторая подписка на конкретный выход (без параметра = primary).
- Панель «Выходы»: кнопка «сделать основным» + бейдж ★ (роут `POST /boss/exits/<eid>/primary`). CLI: пункт «Сделать основным (подписка)».
- Wizard: первый выход = основной по дефолту.
- Миграция юзеров: меняешь основной → клиенты подтянут за ≤3ч авто (host=мост неизменен, меняется relay_port в профиле). Мгновенно — обновить подписку в Happ.

**JSON-профиль по каждому выходу:**
- `_client_profiles` доносит `json` в каждой записи (выход × cascade/direct). Раньше JSON был один (primary).
- Скачивание: `/boss/clients/<cid>/profile.json?exit=<eid>&direct=<0/1>` — выбор выхода/режима (без параметров = primary cascade).
- Панель «Клиенты»: «JSON ▾» перечисляет все варианты (копировать + ↓), «Sub сервер ▾» — подписки per-выход.

**MTProto на выбранный выход (per-port) — главное:**
- `Config.mtproto_exit_id` (дефолт для новых портов) + `mtproto_port_exits: {порт: exit_id}` (где развёрнут каждый порт).
- `config.mtproto_exit(cfg)` (дефолт-выход) + `config.mtproto_port_exit(cfg, port)` (выход порта; незамаплен → exit_servers[0]).
- Форма «+ Порт» (панель) и меню (CLI) — дропдаун выбора выхода. `mtproto_add` пишет `mtproto_port_exits[port]=выход`.
- **rotate/remove/restart бьют в выход КОНКРЕТНОГО порта** (`mtproto_port_exit`), не в глобальный [0] — иначе при смене выхода ломались порты на старом сервере (DNAT и mtg расходились). Панель + CLI.
- `exits_ip` (смена IP выхода) переносит только mtg-порты ЭТОГО выхода.
- **`monitor.decide_targets` + `run_check`** теперь тоже per-port (`mtproto_port_exit`) — раньше проверяли/рестартили все порты на [0]=GER → порт на EST давал ложный красный на дашборде + рестарт не туда. **Это был баг, найденный code-review + пропущенный при первой правке.**

**Pitfalls новые:**
- **raw-iperf3 = не скорость.** Кнопка «Тест скорости» в панели (iperf3 мост↔выход) мерит голый TCP, который DPI душит. Реальная ёмкость — fast.com через туннель. Запись в §15 про «iperf3 ~90 Мбит = ёмкость» — тоже кривая метрика.
- **TELEMT (bridge MTProto) остаётся на [0]** — намеренно вне per-port (отдельный механизм, §16).
- **MTProto «слушает» ≠ «работает через ТСПУ».** mtg на EST:8455 active+LISTEN, монитор зелёный (TCP с моста доходит), но пробивает ли Fake-TLS ТСПУ — проверять только с телефона из РФ.

**Тесты: 164/164.** Планы: `docs/superpowers/plans/2026-06-08-{primary-exit-subscription,exit-selection-mtproto-sni-diag,per-exit-json-and-subscription}.md`. SNI-скан и диагностика-тесты получили выбор выхода (дропдаун); логи уже были по всем выходам.
