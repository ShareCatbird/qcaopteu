# Защита VPN-ноды от Abuse, флуда и т.д

Пошаговое руководство по настройке защиты VPS на Ubuntu 24.04 с использованием nftables для VLESS-ноды.

После настройки ноды остаются открыты 22,443,8443,2222 порты.

![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04-E95420?style=flat&logo=ubuntu&logoColor=white)
![nftables](https://img.shields.io/badge/Firewall-nftables-blue?style=flat)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

# Предисловие

Данное решение было разработано т.к я получил блокировку VPN-ноды за abuse. Аллерт прилетел от spamhaus. После расследования выяснилось, что некоторые пользователи VPN-сервиса (их устройства) заражены вредоносным ПО. Скорее всего это касается смартфонов на Android и ПК на OC Windows. Собственно устройства этих пользователей были как боты для кукловодов (хакеров), которые использовали устройства пользователей для ддос атак на различные сайты, создания proxy fastflux* прокладки устройства для распростронения вредноносного ПО и т.д.

Собственно а откуда произошло заражение у пользователя? Дак эти ваши "бесплатые VPN 2026" из PlayMarket, сомнительных сайтов для Windows. Ещё раз убеждаемся в том, что бесплатный сыр только в мышеловке. Поэтому решение, которое я разработал совместно с Cloud AI (Max версия) решает задачу с килентами у которых устройство превратилось в зомби. Протестировано на 4-х нодах. Полет отличный.

*FastFlux - Это технология, которую используют злоумышленники для скрытия вредоносных серверов. Она предполагает частую смену IP-адресов, ассоциированных с доменами, что затрудняет обнаружение и блокировку.

**Пример работы статистики sudo fw-stats.sh с блокровками**

<img width="625" height="700" alt="123222" src="https://github.com/user-attachments/assets/66b33bce-648c-4247-b13e-0751e1198723" />


## Возможности

| Защита | Описание |
|--------|----------|
| **Blocklist IN** | Блокировка входящих соединений от вредоносных IP |
| **Blocklist OUT** | Блокировка исходящих соединений к вредоносным IP |
| **SYN-flood защита** | Лимит 50 SYN/сек + 150 соединений/мин с одного IP |
| **Anti-scan** | Блокировка невалидных TCP флагов |
| **ICMP лимит** | Ограничение 5 пинг/сек |
| **SSH защита** | Лимит 5 подключений/мин |
| **Автообновление** | Blocklist обновляется каждые 6 часов |
| **Логирование** | Все блокировки записываются в журнал |

---

## Пути хранения логов и источники блоквировок

- Обновления blocklist - /var/log/blocklist.log - cat /var/log/blocklist.log (команда для просмотра лога)
- Блокировки firewall - systemd journal (ядро) - sudo journalctl -k (команда для просмотра лога)
- [Spamhaus DROP - Спам-сети, hijacked блоки](https://www.spamhaus.org/drop/drop.txt)
- [Spamhaus EDROP - Расширенный DROP](https://www.spamhaus.org/drop/drop.txt)
- [FireHOL L1 - Самые опасные: spamhaus, dshield, feodo](https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset)
- [FireHOL L2 - L1 + дополнительные источники](https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset)
- **ИТОГ:** 40.000+ опасных диапазонов IP до auto-merge оптимизации в скрипте
- Ичточник FireHOL автоматически собирает опасные (по разным причинам) IP со всего мира.
- Ознакомиться с мониторингом можно здесь - https://iplists.firehol.org

---

## Требования

- Ubuntu 24.04 LTS
- Root-доступ или sudo
- Доступ к VNC/KVM консоли (на случай блокировки SSH)
- sudo apt install nftables curl -y

> [!CAUTION]
> Перед началом настройки убедитесь, что у вас есть доступ к VNC/KVM консоли вашего хостера. В случае ошибки в правилах вы можете потерять SSH-доступ к серверу.

---

## Пошаговая инструкция по установке

**1 - Подготовка системы**
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install nftables curl -y
sudo systemctl enable nftables
```

**2 - Создание конфигурации nftables**
```bash
sudo mkdir -p /etc/nftables.d
sudo nano /etc/nftables.conf
```

**3 - Вставить в nftables.conf**
```bash
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    
    # Blocklist (Spamhaus + FireHOL)
    set blocklist_v4 {
        type ipv4_addr
        flags interval
        auto-merge
        size 131072
    }

    # Трекинг соединений
    set conn_limit {
        type ipv4_addr
        size 65535
        flags dynamic,timeout
        timeout 30s
    }

    chain input {
        type filter hook input priority 0; policy drop;

        # Loopback
        iif "lo" accept

        # Блокируем входящие ОТ опасных IP
        ip saddr @blocklist_v4 limit rate 10/minute log prefix "[BLOCKLIST IN] " drop

        # Установленные соединения
        ct state established,related accept

        # Невалидные пакеты
        ct state invalid drop

        # Защита от SYN-флуда
        tcp flags syn limit rate 50/second burst 100 packets accept

        # Лимит соединений с одного IP
        tcp flags syn ct state new \
            add @conn_limit { ip saddr limit rate over 150/minute } drop

        # Защита от сканирования портов
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0 drop
        tcp flags & (fin|syn) == (fin|syn) drop
        tcp flags & (syn|rst) == (syn|rst) drop
        tcp flags & (fin|rst) == (fin|rst) drop
        tcp flags & (fin|ack) == fin drop
        tcp flags & (urg|ack) == urg drop

        # ICMP
        ip protocol icmp icmp type { echo-request, echo-reply } \
            limit rate 5/second accept
        ip6 nexthdr icmpv6 icmpv6 type { echo-request, echo-reply } \
            limit rate 5/second accept

        # VLESS порты
        tcp dport { 443, 2222, 8443 } accept

        # SSH
        tcp dport 22 ct state new limit rate 5/minute accept

        # Логируем остальное
        limit rate 5/minute log prefix "[NFTABLES DROP] " drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;

        # Разрешаем loopback (локальный DNS и сервисы)
        oif "lo" accept

        # Разрешаем локальные/приватные сети
        ip daddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept

        # Блокируем исходящие К опасным IP
        ip daddr @blocklist_v4 limit rate 10/minute log prefix "[BLOCKLIST OUT] " drop
    }
}
```

**4 - Создание скрипта обновления blocklist**
```bash
sudo nano /usr/local/bin/update-blocklist.sh
```

**5 - Вставить в update-blocklist.sh**
```bash
#!/bin/bash

# Источники блокировок
SPAMHAUS_DROP="https://www.spamhaus.org/drop/drop.txt"
SPAMHAUS_EDROP="https://www.spamhaus.org/drop/edrop.txt"
FIREHOL_L1="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
FIREHOL_L2="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset"

TEMP_FILE="/tmp/blocklist_combined.txt"
NFT_FILE="/etc/nftables.d/blocklist.nft"

mkdir -p /etc/nftables.d

echo "[$(date)] Загрузка списков блокировки..."

# Загружаем все списки
{
    echo "# Spamhaus DROP"
    curl -s --max-time 30 "$SPAMHAUS_DROP" | grep -v "^;" | grep -v "^$" | awk '{print $1}'
    
    echo "# Spamhaus EDROP"
    curl -s --max-time 30 "$SPAMHAUS_EDROP" | grep -v "^;" | grep -v "^$" | awk '{print $1}'
    
    echo "# FireHOL Level 1"
    curl -s --max-time 60 "$FIREHOL_L1" | grep -v "^#" | grep -v "^$"
    
    echo "# FireHOL Level 2"
    curl -s --max-time 60 "$FIREHOL_L2" | grep -v "^#" | grep -v "^$"
    
} | grep -E "^[0-9]" | sort -u > "$TEMP_FILE"

COUNT=$(wc -l < "$TEMP_FILE")

if [ "$COUNT" -lt 100 ]; then
    echo "[$(date)] Ошибка: загружено только $COUNT записей"
    exit 1
fi

echo "[$(date)] Загружено $COUNT уникальных диапазонов IP"

# Генерируем nftables правила
cat > "$NFT_FILE" << EOF
# Blocklist - $(date)
# Источники: Spamhaus DROP/EDROP, FireHOL Level 1/2
# Всего: $COUNT диапазонов

flush set inet filter blocklist_v4

add element inet filter blocklist_v4 {
EOF

# Добавляем элементы
cat "$TEMP_FILE" | tr '\n' ',' | sed 's/,$//' >> "$NFT_FILE"

echo "" >> "$NFT_FILE"
echo "}" >> "$NFT_FILE"

# Применяем правила
nft -f "$NFT_FILE" 2>/dev/null

if [ $? -eq 0 ]; then
    echo "[$(date)] Успешно: $COUNT диапазонов в blocklist"
else
    echo "[$(date)] Ошибка применения правил!"
    exit 1
fi

rm -f "$TEMP_FILE"
```

**5 - Сохраняем и делаем исполняемым файл update-blocklist.sh**
```bash
sudo chmod +x /usr/local/bin/update-blocklist.sh
```

**6 - Настройка sysctl (защита на уровне ядра)**
```bash
sudo nano /etc/sysctl.d/99-security.conf
```

**7 - Вставить в 99-security.conf**
```bash
# Защита от SYN-флуда
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2

# TIME_WAIT
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1

# Защита от спуфинга
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Отключаем ICMP редиректы
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Отключаем source routing
net.ipv4.conf.all.accept_source_route = 0

# Логирование подозрительных пакетов
net.ipv4.conf.all.log_martians = 1
```

**8 - Сохраняем файл и применяем**
```bash
sudo sysctl --system
```

**9 - Создание systemd сервиса для автозагрузки blocklist**
```bash
sudo nano /etc/systemd/system/blocklist-update.service
```

**10 - Вставляем blocklist-update.service**
```bash
[Unit]
Description=Update IP Blocklist
After=nftables.service
Requires=nftables.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/update-blocklist.sh

[Install]
WantedBy=multi-user.target
```

**11 - Активируем**
```bash
sudo systemctl daemon-reload
sudo systemctl enable blocklist-update.service
```

**12 - Применение правил**
```bash
# Проверяем синтаксис
sudo nft -c -f /etc/nftables.conf

# Применяем правила
sudo nft -f /etc/nftables.conf

# Загружаем blocklist
sudo /usr/local/bin/update-blocklist.sh
```

**13 - Настройка cron (автообновление + резервный автозапуск)**
```bash
sudo crontab -e
```

**14 - Вставить в файл крона**
```bash
# Обновление blocklist каждые 6 часов
0 */6 * * * /usr/local/bin/update-blocklist.sh >> /var/log/blocklist.log 2>&1

# Резервный запуск при загрузке/падении VPS
@reboot sleep 90 && /usr/local/bin/update-blocklist.sh >> /var/log/blocklist.log 2>&1
```

**15 - Создание скрипта статистики**
```bash
sudo nano /usr/local/bin/fw-stats.sh
```

**16 - Вставляем в файл fw-stats.sh**
```bash
#!/bin/bash

echo "=== Статистика Firewall ==="
echo ""

echo "--- Входящие блокировки (24ч) ---"
sudo journalctl -k --since "24 hours ago" 2>/dev/null | grep "BLOCKLIST IN" | \
    grep -oP 'SRC=\K[0-9.]+' | sort | uniq -c | sort -rn | head -10

echo ""
echo "--- Исходящие блокировки (24ч) ---"
sudo journalctl -k --since "24 hours ago" 2>/dev/null | grep "BLOCKLIST OUT" | \
    grep -oP 'DST=\K[0-9.]+' | sort | uniq -c | sort -rn | head -10

echo ""
echo "--- Всего блокировок ---"
echo "Blocklist IN:  $(sudo journalctl -k --since "24 hours ago" 2>/dev/null | grep -c "BLOCKLIST IN")"
echo "Blocklist OUT: $(sudo journalctl -k --since "24 hours ago" 2>/dev/null | grep -c "BLOCKLIST OUT")"
echo "Другие:        $(sudo journalctl -k --since "24 hours ago" 2>/dev/null | grep -c "NFTABLES DROP")"

echo ""
echo "--- Размер blocklist ---"
LOADED=$(grep "Всего:" /etc/nftables.d/blocklist.nft 2>/dev/null | grep -oP '\d+')
MERGED=$(sudo nft list set inet filter blocklist_v4 2>/dev/null | grep -c "/")
echo "Загружено: $LOADED диапазонов"
echo "После оптимизации (auto-merge): $MERGED диапазонов"
```

**17 - Сохрани и сделай исполняемым:**
```bash
sudo chmod +x /usr/local/bin/fw-stats.sh
```

**18 - Проверка работы**
```bash
# Проверяем правила
sudo nft list ruleset

# Проверяем blocklist
sudo nft list set inet filter blocklist_v4 | head -20

# Проверяем порты
sudo nft list chain inet filter input | grep dport

# Проверяем исключения в output
sudo nft list chain inet filter output

# Проверяем автозапуск systemd
sudo systemctl is-enabled nftables
sudo systemctl is-enabled blocklist-update.service

# Проверяем cron
sudo crontab -l

# Проверяем DNS (должен работать)
nslookup google.com

# Статистика
sudo fw-stats.sh
```

**Команды для мониторинга**
```bash
# Реалтайм логи
sudo journalctl -f -k | grep -E "BLOCKLIST|NFTABLES"

# Блокировки за час
sudo journalctl -k --since "1 hour ago" | grep "BLOCKLIST"

# Статистика
sudo fw-stats.sh

# Лог обновлений blocklist
cat /var/log/blocklist.log
```

**Общая структура**
```bash
/etc/nftables.conf                           - основной конфиг
/etc/nftables.d/blocklist.nft                - blocklist (автогенерация)
/etc/sysctl.d/99-security.conf               - параметры ядра
/etc/systemd/system/blocklist-update.service - автозагрузка blocklist
/usr/local/bin/update-blocklist.sh           - скрипт обновления
/usr/local/bin/fw-stats.sh                   - статистика
/var/log/blocklist.log                       - лог обновлений
```
