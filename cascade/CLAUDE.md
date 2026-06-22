# cascade — заметки для будущих сессий

> ⚠️ **РЕПО БЕЗОПАСЕН КАК ПУБЛИЧНЫЙ:** не вписывать реальные IP/домены/ASN/хостеров/провайдеров в код/доки/планы/тесты (деанон-палево). В доках — описательные плейсхолдеры (`<МОСТ_IP>`/`<ВЫХОД_IP>`/`example.com`), без IP-образных строк и имён хостеров. В тестах — синтетические фикстуры. Реальное — только в `/etc/cascade/config.json` на сервере.

## Архитектура
- CLI всегда на РФ-сервере (мост). К каждому серверу выхода ходит по SSH (vendored `ssh.py` из meridian, MIT).
- Серверы выхода (несколько): Xray (raw `config.json` + systemd) + mtg на первом (systemd). НЕ 3x-ui/Docker/nginx.
- РФ-мост: iptables DNAT (правило на выход) + cron-мониторинг + Telegram-бот + веб-панель (`cascade --panel` за Caddy).
- Один конфиг: `/etc/cascade/config.json` (выходы, клиенты, креды, панель).

## Схема Config (ключевые поля)
- `exit_servers: list[ExitServer]` — несколько выходов. У каждого свои `reality_private_key/public_key/short_id`, `relay_port` (порт на мосту, уникален), `vpn_port` (порт Xray на выходе), `vpn_sni`, `vpn_xhttp_*`, `id`, `location`.
- `clients: list[Client]` — `{id, name, uuid, enabled, created}`; один uuid живёт на ВСЕХ выходах; email в Xray = имя клиента.
- `vpn_name: str` — название в `#fragment` VLESS-ссылки.
- `mtproto_ports` / `mtproto_secrets` — mtg на ПЕРВОМ выходе (`exit_servers[0]`).
- Миграция старого single-exit формата → `load_config._migrate` (idempotent).
- Профили: `client_profile_json/url(uuid, exit, relay_ip, direct=)` — cascade (мост) vs direct (выход напрямую).
- `panel`/`domain`/`share_tokens` — веб-панель. `panel/auth.py` (pbkdf2 stdlib `hash_password`/`verify_password`), `panel/share.py` (`add_share`/`find_valid` TTL/`revoke`). Пароль/домен — в CLI «Настройки» или «Веб-панель».

## Веб-панель (`cascade/panel/`, готово)
- `app.py` `create_app(config_path, secret_path)` → Flask. Роуты: `/` (decoy, БЕЗ слов vpn/vless/proxy — анти-фингерпринт), `/robots.txt` (Disallow: /), `/boss` (логин GET/POST + CSRF-токен в сессии), `/boss/` (dashboard, `login_required`), `/boss/logout`, `/boss/clients|exits|settings`, публичная `/c/<токен>` (профили cascade+direct + inline-SVG QR `qrencode`; невалидный токен → decoy). Секрет сессии — `/etc/cascade/panel_secret` (0600).
- Запуск: `cascade --panel` (waitress 127.0.0.1:`panel.port`, ветка `__main__._serve_panel`) за Caddy (авто-TLS по домену, reverse_proxy). `panel/deploy.py`: `caddyfile`/`panel_unit` (чистые, тестируемы) + `apply_panel` (пишет Caddyfile+systemd, поднимает — на мосту). CLI `panel_menu` включает. install.sh ставит Caddy.
- Pitfalls панели: роуты сохраняют в `config_path` (`save_config(c, config_path)`, НЕ дефолт); SSH-POST (add/remove client) в try/except (не валим 500); добавление ВЫХОДА — только через CLI (долгий SSH-деплой); Caddy стандартный — без rate_limit (fail2ban опц.). Тесты — Flask test client, `_relay_ip`/`_qr_svg`/`check_once` мокаются.

## Безопасность панели (внедрено)
- **Cookie**: `SESSION_COOKIE_SECURE=True`, `SESSION_COOKIE_SAMESITE="Lax"` — в `create_app()`.
- **Caddy security headers** (`panel/deploy.py` → `caddyfile()`): HSTS 1 год, X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy no-referrer, CSP default-src 'self', X-Robots-Tag noindex, `-Server` (убирает waitress/Caddy из ответов).
- **Bot/scanner блокировка** (Caddy `@blocked` matcher): sqlmap, nikto, masscan, zgrab, nuclei, ffuf, gobuster, поисковики (Google/Yandex/Bing/etc), python-requests, Go-http-client → 404.
- **Идентификация**: title/лого не содержат "CASCADE VPN" — `/boss` показывает "Вход", sidebar — "⬡", `/c/<токен>` — "Настройки".
- **Деплой Caddyfile** (после правок `deploy.py`): `python3 -c "from cascade.panel.deploy import caddyfile, PANEL_CADDY_PATH; from cascade.config import load_config, CONFIG_PATH; c = load_config(CONFIG_PATH); open(PANEL_CADDY_PATH,'w').write(caddyfile(c.domain, c.panel.port))" && systemctl reload caddy`
- **Деплой**: `install.sh` ставит editable (`pip install -e .`). Обновление: `git pull && systemctl restart cascade-panel`.

## Pitfalls
- **XHTTP inbound**: `flow` ДОЛЖЕН быть `""` (vision-flow ломает XHTTP). См. `_reality_inbound`.
- **shlex.quote**: все интерполяции в `conn.run()` оборачивать.
- **host в VLESS-ссылке** = IP РФ-сервера (relay), НЕ сервера выхода.
- **Секрет mtg**: `ee` + 32 hex (16 random байт) + hex(домен), длина чётная.
- **`build_xray_config`** принимает `clients: dict`, НЕ `uuid: str`. Все клиенты в одном inbound.
- **`_rebuild_xray(conn, cfg)`**: вызывать при ЛЮБОМ изменении клиентов/SNI — пересобирает config.json и делает `systemctl restart xray`.
- **`load_config`**: неизвестные ключи JSON отбрасываются (forward-compat); `_migrate` конвертит старый single-exit (`exit_server`+`vpn_clients`+top-level reality-ключи) → `exit_servers[]`+`clients[]` (idempotent).
- **relay-порты мульти-выхода**: `relay_port` уникален на мосту (DNAT-вход), `vpn_port` — порт Xray на выходе. Монитор и direct-профиль бьют в `ip:vpn_port`, cascade-профиль и DNAT-вход — `relay_port`. Новый выход в `exits_menu` берёт `relay_port = max(существующих)+10`.
- **`xray x25519`**: парсер поддерживает 2 формата вывода (classic + новый). На живом сервере свериться.
- **Клиентский профиль** (`build_client_xray_config`): split-туннель РФ→direct, прочее→каскад. host = IP моста (РФ). split-DNS: РФ → Яндекс 77.88.8.8, прочее → Google DoH `dns.google`. Только Xray-core клиенты (Happ/OneXray/v2rayNG/Nekoray/NekoBox); Karing (sing-box) отброшен.
- **relay MASQUERADE**: НЕ в `dnat_rules` (общий на iface). `apply_rule` ставит через `_ensure_masquerade` идемпотентно (`iptables -C`), `remove_rule` его не трогает. Важно для будущего мульти-выхода: один MASQUERADE на все правила.
- **Сетевой тюнинг (BBR/fq/буферы/MTU + conntrack liberal)**: транспорт каскада = VLESS+Reality поверх **raw TCP** → TCP-в-TCP. Мост: `relay._ensure_net_tuning()` (BBR+fq+mtu_probing=1+буферы 16M+**nf_conntrack_tcp_be_liberal=1** → `/etc/sysctl.d/99-cascade-net.conf` + `tcp_bbr` в `/etc/modules-load.d/`) и `relay._ensure_mss_clamp()` (`--set-mss 1340` фиксированный на FORWARD) — оба идемпотентны, вызываются в `apply_rule`. Выход: `vpn._tune_exit()` (тот же sysctl по SSH) в `deploy_vpn`. Флаг `nf_conntrack_tcp_be_liberal=1` критичен: ТСПУ инжектирует RST с неверным ACK → без флага conntrack помечает INVALID → nfqws не перехватывает → разрыв. `--set-mss 1340` вместо `--clamp-mss-to-pmtu` — фиксированный MSS стабильнее при TCP-in-TCP.
- **zapret/nfqws (DPI-десинхронизация)**: `relay._ensure_zapret(target_ip, port)` — ставит nfqws, запускает systemd-юнит `cascade-zapret`, добавляет iptables `mangle FORWARD` правило. Запускается в `apply_rule()`. Ключевые параметры: `FORWARD` (не POSTROUTING — DNAT-транзит), `connbytes 0:6` (только хендшейк), `mark 0x40000000` (анти-петля), `--queue-bypass` (при падении nfqws → ACCEPT). nfqws нет в Ubuntu-репах → сборка из bol-van/zapret; нужен `libcap-dev` сверх стандартного build-essential. Сборка медленная если делать внутри Python с `capture_output=True` — кажется завис; запускай вручную если подвисло.
- **Фингерпринт (`Config.fingerprint`)**: uTLS-отпечаток — ТОЛЬКО клиентский (серверный `_reality_inbound` параметр fingerprint не эмитит, мёртвый). Список — `xray_config.FINGERPRINTS`. Глобальный, пробрасывается в `client_profile_json`/`client_profile_url` → `realitySettings.fingerprint` (JSON) и `&fp=` (ссылка). Смена fp = только перегенерация профилей, БЕЗ SSH/редеплоя. Клиенты на статичном JSON/ссылке должны переимпортировать (fp зашит в их конфиг). При DPI-блокировках chrome помогает firefox. CLI: Настройки → Фингерпринт; панель: Настройки → select.
- **`xray.service` `User=nobody`**: офиц. инсталлер Xray ставит его, systemd на Ubuntu 24 спамит «not safe». `vpn._install_xray` убирает строку + `daemon-reload` после установки.
- **Тесты**: запускать `python3 -m pytest tests/` — не голый `pytest` (подхватит meridian-main/tests).

## Веб-панель: inline-CRUD (2026-06-02)
- **CSP-pitfall (баг копирования):** Caddy CSP = `default-src 'self'` → браузер блокирует инлайн `onclick`/`onsubmit`. Поэтому весь JS в `static/app.js` (грузится `<script src>`, разрешён `'self'`), обработчики через `data-copy`/`data-confirm` + делегирование. **НЕ возвращать инлайн-обработчики** — копирование/подтверждения снова умрут. `'unsafe-inline'` для script НЕ добавлять (XSS).
- **Навигация 4 пункта:** Дашборд / Клиенты / Выходы / Настройки. MTProto слит в «Клиенты» (`/boss/mtproto` GET → redirect на clients). Share+Логи — суб-табы внутри «Настройки» (`_subtabs.html`, отдельные роуты, логи ленивы).
- **MTProto-управление в панели:** `mtproto_add`/`mtproto_rotate`/`mtproto_remove` (+`restart`). mtg 2.x = 1 секрет/инстанс → **порт-на-юзера**. Метки юзеров в `Config.mtproto_labels` ({«порт»:«имя»}). Ротация секрета = `deploy_mtproto(port, domain, new_secret)` перезаписывает systemd-юнит. `remove_mtproto` чистит юнит.
- **Проверка коллизии портов (3 слоя):** `config.used_ports(cfg)` (relay/vpn/xhttp/mtproto) → `relay.port_listening(port)` (ss на мосту) → `mtproto.exit_port_listening(conn, port)` (ss по SSH на выходе). Порядок add: валидация → deploy → relay → save (без half-state). Используется в `mtproto_add` и `exits_port`. Авто-подсказка свободного порта = max(used)+1.
- **Смена IP выхода (`exits_ip`):** `deploy_vpn` теперь генерит reality-ключи ТОЛЬКО если их нет (`if not reality_private_key`). При смене IP ключи сохраняются → **cascade-ссылки клиентов живут** (host=мост неизменен, меняется лишь DNAT-таргет). mtg на первом выходе переносится на новый IP с теми же секретами. Direct-профили (host=exit.ip) ломаются — это норма.
- **Клиенты:** `vpn.set_client_enabled` (toggle, нельзя выключить последнего активного) и `vpn.rename_client` (имя=email → rebuild для синка, id/uuid/share-токены стабильны). Копия vless (cascade/direct, все выходы) + QR в строке через `<details>` (нативный HTML, CSP-safe). Share с кастомным TTL (24ч/3д/7д).

## Не проверено на живом сервере
- `deploy_vpn`, `deploy_mtproto`, `add_vpn_client`/`remove_vpn_client` (синк по неск. выходам), `change_sni`.
- **Панель inline-CRUD (2026-06-02):** mtproto add/rotate/remove на живом выходе, проверка портов (ss), смена IP выхода (редеплой + перенос mtg), client toggle/rename (rebuild). Копирование vless/tg в браузере (CSP+clipboard secure-context).
- `relay.apply_rule` с разными `relay_port` на одном мосту; формат вывода `xray x25519`.
- Клиентский профиль на устройстве: РФ-сайт → РФ IP (2ip.ru), иностранное → выход; direct-профиль (минуя мост). DoH `dns.google` — bootstrap; при зацикливании → `https://8.8.8.8/dns-query`.
- **Веб-панель на живом мосту:** `cascade --panel` + Caddy: ACME-сертификат (открыть 80/443 + A-запись домена), `/`→decoy, `/boss` логин, `/c/<токен>`→профили+QR.

## Сессия 2026-06-05 (важные изменения)
- **Telegram идёт через каскад, не через MTProto.** В `build_client_xray_config` убраны правила `domain:t.me→proxy` и `geosite:telegram→direct` — TG (домены+IP не-РФ) падает в catch-all→proxy (Reality/firefox-fp). Причина: **standalone MTProto в РФ мёртв** — ТСПУ с 01.04.2026 блочит Fake-TLS по JA3/JA4 ClientHello. mtg обновлён до 2.2.8 + свежее приложение Telegram — всё равно блок (у mtg нет ротации fp как uTLS у Xray). mtg оставлен (8443/45/46 + 8447=test yahoo.com) idle на случай смены ситуации. **Не возвращать telegram→direct правила.**
- **Fingerprint uTLS** (`Config.fingerprint`, `xray_config.FINGERPRINTS`, дефолт **firefox** — chrome режет РФ-DPI). Только клиентский, пробрасывается в `client_profile_json`/`client_profile_url`. CLI: Настройки→Фингерпринт; панель: Настройки→select. Подробнее в [[verify-topology-not-vacuum]]/PROJECT.md.
- **GER переустановлен (Ubuntu 22.04).** Было 24.04 — `ssh.socket` не переживал ребут, рвал sshd на kex → SSH к GER умирал. 22.04 = classic `ssh.service`, переживает. sshd слушает 22+2222 (`/etc/ssh/sshd_config.d/cascade-port.conf`); **мост ходит на 2222** (провайдер RU-провайдер режет 22 с IP моста). Передеплой переиспользует reality-ключи+mtproto-секреты из конфига → клиентские ссылки выживают. Конфиг моста = источник правды (бэкап перед переустановкой!).
- **Фриз ленты был серверным, не маршрутным.** После переустановки GER iperf3 GER→мост = ~90 Мбит (было 1-2). Прошлый диагноз «битый маршрут RU-провайдер» неверен — гнил сам инстанс. Ёмкость: ~15-20 активных видео / ~50-80 смешанных юзеров.
- **Панель:** `_ensure_host_key(ip,port)` авто-добавляет host-key выхода перед `check_ssh` (в вебе нет TTY) — фикс «Проверить SSH+TCP». waitress: 8 потоков + логгер `waitress.queue`→ERROR (убран спам «Task queue depth»). Диагностика: одна кнопка **«Тест скорости» (iperf3 мост↔выход, scope `bridge_shell`)** + «Полная диагностика» (speed+ss+ping+exit_speed); таймаут speed=120с.
- Тесты **96/96**. **НЕ доделано: подписка Happ** — план `docs/superpowers/plans/2026-06-05-happ-subscription.md`.

## Сессия 2026-06-07 (zapret + conntrack liberal)
- Тесты **127/127**.
- **zapret/nfqws**: добавлен в `relay.apply_rule()`. nfqws нет в Ubuntu → собирается из bol-van/zapret; зависимости: `build-essential libnetfilter-queue-dev libnfnetlink-dev libmnl-dev libcap-dev`. `cascade-zapret` systemd active на мосту <МОСТ_IP>.
- **nf_conntrack_tcp_be_liberal=1**: добавлен в `_NET_TUNING`. Применён на мосту.
- **MSS clamp**: исправлен с `--clamp-mss-to-pmtu` на `--set-mss 1340`.
- **Sniffing выхода**: убран из `_reality_inbound()`. GER Xray перестроен с моста через `_rebuild_xray`.
- **Деплой на живое выполнен**: мост + GER оба актуальны (коммит 471c596).

## Принцип: zero-downtime при изменении серверных параметров (2026-06-06)
**Любое изменение параметра, зашитого в клиентский профиль, = breaking change если просто перезаписать.**
Reality `serverNames`, порт, `shortId`, `publicKey` — всё это лежит в VLESS-ссылке/JSON клиента.

**Правило:** при смене критического параметра держать старое значение параллельно, пока клиенты не обновили подписку.

**Реализация SNI-rotation (пример):**
- `ExitServer.vpn_sni_legacy: list` — старые SNI при смене
- `serverNames` в Xray = `[текущий] + legacy` — Xray принимает оба
- `change_sni()` пушит старый в legacy, НЕ удаляет
- Панель показывает `⚠ legacy: google.com [очистить]` — admin чистит вручную
- Только после очистки старый SNI перестаёт приниматься

**Клиентский профиль содержит** (минимальный список breaking-параметров): `sni`, `port`, `pbk` (publicKey), `sid` (shortId). Смена любого = нужен аналогичный механизм или заблаговременное уведомление.

**Подписка решает** — клиенты с `sub_token` получают новые параметры при следующем обновлении подписки (авто раз в сутки в большинстве приложений). Поэтому подписка предпочтительнее статичных ссылок.

## Источники (reuse)
- `ssh.py` — meridian (MIT); мёртвый код удалён, осталось: `run`/`write_file`/`check_ssh`/`tcp_connect`.
- VLESS-ссылки/streamSettings — референс из meridian `protocols.py`/`provision/xray.py`.
- relay iptables — из compmaniya (`VPN/install.sh`).
- mtg-логика — из `mtproto/install.sh` (78ers/mtproto).

## Сессия 2026-06-08 (основной выход + подписка с выбором + MTProto per-port)
- Тесты **164/164**. Полная картина — PROJECT.md §17. Планы: `docs/superpowers/plans/2026-06-08-*`.
- **`primary_exit_id` + `config.primary_exit(cfg)`** — выход, который отдаёт подписка `/sub`. Дефолт [0]. Панель «Выходы»→«сделать основным»+бейдж ★; CLI пункт; wizard ставит первый. `/sub` интервал **24→3ч**.
- **Подписка с выбором сервера: `/sub/<token>?exit=<eid>`** (без параметра = primary). Вторая подписка на конкретный выход. JSON-скачивание тоже: `/profile.json?exit=&direct=`.
- **JSON-профиль теперь по КАЖДОМУ выходу×режиму** (`_client_profiles` доносит `json`), не только primary. Панель: «JSON ▾» все варианты, «Sub сервер ▾» per-выход.
- **MTProto per-port (важно):** `mtproto_exit_id` (дефолт для новых портов) + `mtproto_port_exits: {порт: exit_id}` (где развёрнут каждый). `config.mtproto_exit()` / `config.mtproto_port_exit(cfg, port)` (незамаплен → [0]).
  - **rotate/remove/restart бьют в выход КОНКРЕТНОГО порта** (`mtproto_port_exit`), НЕ в глобальный [0]. Иначе при смене выхода ломались порты на старом сервере (DNAT↔mtg расходились). Панель + CLI + **monitor** (`decide_targets`/`run_check`).
  - **monitor был багом:** проверял/рестартил все mtg-порты на [0]=GER → порт на EST давал ложный красный на дашборде. Найдено code-review, пропущено при первой правке. Теперь per-port.
- **raw-iperf3 мост↔выход = НЕвалидная метрика скорости.** ТСПУ DPI душит голый TCP (EST raw=0 байт), а через Reality 48 Мбит. Реальная скорость — fast.com через каскад. Кнопка «Тест скорости» в панели врёт. См. память `project_cascade_speedtest_metric`.
- **MTProto «слушает» ≠ «работает через ТСПУ».** mtg active+LISTEN на выходе → монитор зелёный (TCP с моста доходит), но Fake-TLS ТСПУ может резать — проверять только с телефона из РФ. mtg Fake-TLS мёртв в РФ (с 01.04.2026); живой кандидат = TELEMT (bridge), он на [0], вне per-port (намеренно).

## Сессия 2026-06-22 (бэкап + deep-probe + альтернативные транспорты PoC)
- Тесты **180/180**. Полная картина — PROJECT.md §18. Коммиты `f0c8550`, `15a2269`.
- **Живой A/B raw TCP vs XHTTP на одном выходе = разницы нет.** raw-TCP-Reality НЕ задушен; XHTTP прироста не даёт. **Текущий raw TCP оставляем.** XHTTP-код = страховка. (Ранний вывод «XHTTP вытащил GER 3→80» — РЕТРАКЦИЯ: сравнивал с устаревшей цифрой, не контроль.)
- **XHTTP клиентский профиль:** `build_client_xray_config(xhttp_path=...)` (дефест="" → прежний tcp+vision, аддитивно), `client_xhttp_profile_json/url`, `vless_xhttp_reality_url`. Серверный inbound + DNAT моста были раньше. Роутинг транспорт-независим — XHTTP-JSON несёт тот же сплит, голая ссылка нет.
- **`cascade/hysteria.py` (новый):** Hysteria2 PoC по SSH (Salamander, self-signed+pinSHA256, UDP) + hy2-ссылка. Живьём: UDP проходит (ТСПУ НЕ блокирует), но QUIC не достраивается до LTE-CGNAT-мобилы. Причина (консультанты): MTU + l4-25 packet-limit. Припаркован (в Happ ещё и теряет роутинг — URI-only). **Happ 4.11 выпилил allowInsecure → hy2 нужен `pinSHA256`, не `insecure=1`.**
- **`cascade/backup.py` (новый):** `backup_config` (ротация 7) + `install_backup_cron` (cron.d, без CLI). Панель Настройки→Сервер: «Скачать бэкап» (`/boss/config/download`, off-server DR) + «Бэкап сейчас + авто» (`/boss/config/backup`).
- **monitor:** `tls_handshake_ok` (deep-probe — реальный TLS-хендшейк, ловит «слушает но ТСПУ душит») + `conntrack_usage`. Выведены в Диагностику → «Глубокая проверка». `run_check`/авто-рестарт НЕ тронуты.
- **Pitfall:** `exits_remove` (панель) снимает только relay основного порта — НЕ xhttp-порт (орфан). CLI `menu.py` чистит и xhttp/mtproto. TODO дочистить панельную версию.
