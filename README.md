# Пошаговая настройка защиты VPS (от аллертов абуза, флуда и т.д)

Пошаговое руководство по настройке защиты VPS на Ubuntu 24.04 с использованием nftables для VLESS-ноды.

![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04-E95420?style=flat&logo=ubuntu&logoColor=white)
![nftables](https://img.shields.io/badge/Firewall-nftables-blue?style=flat)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

---
## Предисловие


---

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

## Требования

- Ubuntu 24.04 LTS
- Root-доступ или sudo
- Доступ к VNC/KVM консоли (на случай блокировки SSH)

> [!CAUTION]
> Перед началом настройки убедитесь, что у вас есть доступ к VNC/KVM консоли вашего хостера. В случае ошибки в правилах вы можете потерять SSH-доступ к серверу.

---

## Быстрый старт

```bash
# Клонируем репозиторий
git clone https://github.com/yourusername/nftables-vless-protection.git
cd nftables-vless-protection

# Запускаем установку
sudo chmod +x install.sh
sudo ./install.sh
