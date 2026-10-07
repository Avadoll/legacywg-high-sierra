# Использованные компоненты и лицензии

Релизной поставки пока нет. Этот список относится к исходникам этапа A и исследовательским бинарникам. Собственное имя проекта — LegacyWG; продукт не является официальным приложением WireGuard.

| Компонент | Версия | Использование | Лицензия и файл |
| --- | --- | --- | --- |
| wireguard-go | f333402… / 2631ce9… | Неизменённые официальные деревья и исследовательские engine | MIT, LICENSE в каждом Vendor/wireguard-* |
| Go | 1.24.13 | Compiler/runtime исследовательского engine | BSD-3-Clause, Licenses/Go-LICENSE; patent grant — Licenses/Go-PATENTS |
| golang.org/x/crypto | v0.37.0 | Фактически включён в Darwin engine | BSD-3-Clause, Licenses/golang.org_x_crypto-v0.37.0-LICENSE |
| golang.org/x/net | v0.39.0 | Фактически включён в Darwin engine | BSD-3-Clause, Licenses/golang.org_x_net-v0.39.0-LICENSE |
| golang.org/x/sys | v0.32.0 | Фактически включён в Darwin engine | BSD-3-Clause, Licenses/golang.org_x_sys-v0.32.0-LICENSE |
| gvisor.dev/gvisor | v0.0.0-20250503011706-39ed1f5ac29c | Upstream graph/test dependencies; в engine main не включён | Apache-2.0, сохранён LICENSE в Licenses |
| github.com/google/btree | v1.1.2 | Upstream graph/test dependencies; в engine main не включён | BSD-3-Clause, сохранён LICENSE в Licenses |
| golang.org/x/time | v0.7.0 | Upstream graph/test dependencies; в engine main не включён | BSD-3-Clause, сохранён LICENSE в Licenses |
| golang.zx2c4.com/wintun | v0.0.0-20230126152724-0fa3db229ce2 | Windows test dependencies; в Darwin engine не включён | MIT, сохранён LICENSE в Licenses |
| golang.org/x/vuln | v1.8.0 | Только внешний анализатор, вне продукта | BSD-3-Clause; module sum/build dependencies — Evidence/analyzer-buildinfo.txt |
| Go | 1.27.1 | Только сборка анализатора, вне продукта | BSD-3-Clause, .tools/go1.27.1/go/LICENSE; toolchain не входит в исходный ZIP |

В lock перечислен полный upstream module graph. Узлы, исходные архивы которых не требовались выбранному build/test, имеют NOASSERTION и не заявлены включёнными в бинарник. Для каждой фактически включённой зависимости есть проверенный module sum, SHA256 module archive и копия лицензии. Перед релизом требуется финальная проверка состава каждого артефакта, дополнительных NOTICE и лицензий фактически поставляемых файлов.

Код GPL-проектов, wireguard-tools, wireguard-apple и Apple sample не копировался и в сборку не включался. MacPorts использован только как evidence совместимости; его код/бинарник не перепаковывался.
