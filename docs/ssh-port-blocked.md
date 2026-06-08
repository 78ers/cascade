# SSH порт заблокирован: диагностика и фикс

## Симптом

Диагностика в панели (example.com/boss) показывает:
```
ssh: connect to host <ВЫХОД1_IP> port 22: Connection timed out
```
Ping с моста на GER работает. С личного Mac SSH работает.

## Причина

Провайдер GER блокирует порт 22 с IP моста (<МОСТ_IP>) на уровне внешнего файрвола — до Linux на GER пакеты не доходят.

## Диагностика

```bash
# С моста (<МОСТ_IP>):
ping -c 3 <ВЫХОД1_IP>          # проходит — сеть живая
nc -zv -w 5 <ВЫХОД1_IP> 22     # таймаут = внешний файрвол провайдера
nc -zv -w 5 <ВЫХОД1_IP> 8444   # проходит — VPN порты не блокируются
```

## Решение: добавить нестандартный SSH порт на GER

### Шаг 1 — На GER (с личного Mac)

```bash
ssh root@<ВЫХОД1_IP>

# Добавить ОБА порта — 22 оставить чтобы не закрыть доступ с Mac
echo "Port 22" >> /etc/ssh/sshd_config
echo "Port 2222" >> /etc/ssh/sshd_config

# Ubuntu 24.04: отключить socket-активацию (она игнорирует Port в конфиге)
systemctl stop ssh.socket ssh.service
systemctl disable ssh.socket
systemctl start ssh.service

# Проверить — должны быть оба порта
ss -tlnp | grep ssh
```

### Шаг 2 — На мосту: обновить конфиг каскада

```bash
ssh root@<МОСТ_IP>

python3 -c "
import json
with open('/etc/cascade/config.json') as f: d=json.load(f)
for ex in d.get('exit_servers',[]):
    if ex.get('ip')=='<ВЫХОД1_IP>': ex['ssh_port']=2222
with open('/etc/cascade/config.json','w') as f: json.dump(d,f,indent=2)
print('done')
"
```

### Шаг 3 — Проверить и перезапустить панель

```bash
nc -zv -w 5 <ВЫХОД1_IP> 2222
systemctl restart cascade-panel
```

## Особенности Ubuntu 24.04

- Сервис SSH: `ssh`, не `sshd`
- Socket-активация (`ssh.socket`) игнорирует `Port` в sshd_config — нужно отключить
- После `systemctl disable ssh.socket` + `systemctl start ssh.service` SSH читает все порты из конфига
