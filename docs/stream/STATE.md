# Состояние

## Current

**Мост:** версия `d8891e0`, `cascade-panel` active. Копия конфига до режима — `/etc/cascade/config.json.bak-2026-11-22`.

**WeChat (сбой медиа с ~19–20.11.2026, общий для России):**
- Напрямую из России медиа не грузятся — с Happ и без него. Через ссылку direct к эстонскому выходу (без моста) грузятся, через мост — нет.
- Клиентский профиль: DNS доменов WeChat — DoH по IP (DNSPod, AliDNS), маршрут WeChat — напрямую.
- У клиента `default` включён режим `dns_from_json`: Happ берёт DNS туннеля из профиля, WeChat резолвится Google DoH с подсетью China Telecom (узлы в Китае, а не в зарубежном облаке Tencent), плюс 7 доменов WeChat из v2fly. Остальные клиенты без изменений.
- Ждём проверку владельца: переподключить Happ, открыть в WeChat фото, файл, видео.

**Снять режим у `default` (если без эффекта):**

```
cd /opt/cascade && python3 -c 'from cascade.config import load_config,save_config,CONFIG_PATH;c=load_config(CONFIG_PATH);x=[k for k in c.clients if k.name=="default"][0];x.dns_from_json=False;save_config(c,CONFIG_PATH);print(x.name,x.dns_from_json)'
```

Затем на телефоне обновить подписку и переподключить Happ.

**Следующий вариант (решение владельца):** только WeChat — на выход напрямую, в обход моста; остальное без изменений.

**Не в репозитории:** строка в `cascade/CLAUDE.md` про запуск тестов (чужая правка от 24.09, не отправлялась).

Разбор — `DECISIONS.md`, уроки — `LEARNINGS.md`, журнал — `CHANGES/2026-11-22-wechat-dns.md`.
