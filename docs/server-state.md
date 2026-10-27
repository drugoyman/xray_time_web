# Состояние сервера

Источник: живые проверки по SSH 27.10.2026 и данные диагностики 26.10.
Административные пароли и ключи в репозитории отсутствуют.

| Объект | Проверенное значение |
|---|---|
| Публичный IPv4 | 89.19.210.13, интерфейс eth0 |
| DNS | yugoo.su A → 89.19.210.13; 26.10 Google и Cloudflare дали одинаковый ответ |
| AAAA / CNAME | 26.10 ответов для корня yugoo.su не найдено |
| Хостинг | Timeweb; hostname сервера принадлежит twc1.net |
| ОС / ядро | Debian, Linux 6.1.0-54-amd64 |
| Часовой пояс хоста | Europe/Moscow |
| Часовой пояс контейнера | Asia/Tehran в импортированном compose; отличается от хоста |
| Контейнер | 3x-ui, network_mode=host, restart=unless-stopped |
| 3x-ui / Xray | 2.8.8 / 26.1.18 |
| Число подключений в БД | 29 |
| SSH / панель | TCP 22 / HTTPS TCP 4200 |
| Основной VLESS | inbound 43, vless-tls-443-yugoo, TCP 443, TLS |
| SNI | yugoo.su |
| Сертификат VPN | Let's Encrypt, действителен 04.09–03.12.2026 по проверке 26.10 |
| Системный WireGuard | wg-quick@wg0, интерфейс wg0, адрес 10.70.0.1/24 |
| Docker log rotation | json-file, max-size=20m, max-file=3 |

Образ 3x-ui закреплён по digest:

```text
ghcr.io/mhsanaei/3x-ui@sha256:785e71b6711ca887c4a0efb7e5af0abb376263e36093e23f02cab45e137ea78b
```

Image ID локального Docker — другой тип идентификатора:

```text
sha256:abb840ed67b349df33ab8df3533783cb5384156f34e72b4a8bf49c2ab6bffd53
```

## Расположение данных

- SQLite: `/root/3x-ui/3x-ui/db/x-ui.db` → `/etc/x-ui/x-ui.db` контейнера.
- Сертификаты VPN: `/root/3x-ui/3x-ui/cert` → `/root/cert`.
- Сертификат панели: `/etc/vpn-safe/panel-cert/{public.key,private.key}`,
  смонтирован read-only в `/public.key` и `/private.key`.
- Сгенерированный runtime-конфиг: `/app/bin/config.json` внутри контейнера.
- Системный WireGuard: `/etc/wireguard`; не является частью контейнера Xray.
- Локальные резервные копии: `/var/backups/vpn-safe`.
- Состояние проверок: `/var/lib/vpn-safe/health.json`.

Файлы по этим путям могут содержать секреты; в Git включаются только исходники,
а не содержимое эксплуатационных каталогов.

## Что не подтверждено

- Прямой доступ из проблемной сети не восстановлен.
- Успех работы любого iPhone не следует из серверной проверки.
- Выгрузка резервных копий в Drive не подтверждена; последняя попытка неуспешна.
- Дополнительный IP в рамках этой переписки не заказывался и не подключался.
