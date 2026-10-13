# Что требуется для готовой программы

Состояние на 13 октября 2026. Пользователь возобновил работу. Исходный объём ТЗ сохранён; успешная исследовательская сборка не считается готовым продуктом.

| Требование | Текущее доказательство / недостающая работа |
| --- | --- |
| Intel High Sierra 10.13.6, без повышения minimum OS | ObjC compile deployment 10.13 / plist 10.13.6; Go Mach-O minos 11.0 не изменён. Target runtime и установленный patch level не подтверждены. Нужен реальный target test. |
| Официальный встроенный WireGuard, без собственной криптографии | Неизменённое pinned vendor tree, lock verification, native encrypted peer tests. Baseline tag signature проверена по maintainer published key; новый candidate unsigned. Toolchain/OS maintenance остаются открытыми. |
| Стандартные .conf, strict parser, известные параметры, несколько peers | ConfigCore tests/vet/fuzz, bounded parser/UAPI. Native multi-peer routing ещё нужно испытать. AmneziaWG extras явно не поддерживаются. |
| Защита ключей и метаданных | Login Keychain own-app ACL, bounded IPC/private pipes, fixed errors, redacted keys, отключённые core dumps. Нужны locked Keychain/foreign requester/ACL update tests и проверка diagnostic export. |
| Narrow authenticated root boundary | Kernel Mach audit + exact code hashes, root ownership; wrong caller/server rejection. Network component substitution test добавлен в CI. Полный adversarial audit/High Sierra ещё нужны; worker остаётся root. |
| Реальная адресация/handshake/трафик/статус | Native official engine + utun, 20 cycles, real RX/TX/handshake. Требуются freshness/peer-specific state, timeout/cancel и существующий разрешённый server peer. |
| IPv4/IPv6/dual-stack split routes и numeric endpoints | Run 38401449000: native encrypted IPv6, IPv6 endpoint, simultaneous IPv4+IPv6 и IPv6 DNS transport прошли modern CI; High Sierra требует отдельного доказательства. |
| Full routes и physical endpoint escape | Не реализованы. Полные профили отвергаются. Нужны исходные route snapshots/ownership, endpoint host escapes и recovery без изменения чужих маршрутов. |
| Hostname endpoints / bootstrap DNS | Bounded native resolver добавлен, pending macOS CI. Validation без DNS; Start: общий deadline 5s, не более 32 answers, проверка всех AllowedIPs, IPv4 preference/IPv6-only. Bootstrap использует текущую сеть до туннеля; protected reconnect/re-resolution/fallback не реализованы. |
| DNS через native SystemConfiguration | Temporary own session key + process heartbeat реализованы. Run 38399327923 подтвердил real system UDP/TCP DNS через IPv4 tunnel, cleanup при Disconnect/helper crash/agent crash и исходное foreign resolver state. Это не глобальная leak guarantee или доказательство High Sierra; IPv6 transport тестируется отдельно. |
| Fail-closed / IPv6 block / own PF anchor | Не реализованы. Kill switch отсутствует в UI; full tunnel не включается. Нужны coexistence с foreign anchors/states, физический packet capture, уже открытые TCP/UDP connections, crash/reboot recovery. |
| Transaction recovery journal и GUI recovery | Не реализованы для persistent network changes. Текущие собственные utun routes и temporary DNS sessions очищаются при закрытии процессов; этот механизм не заменяет journal для endpoint/PF изменений. |
| GUI profile name/edit/export, status details и menu bar | Import/list/delete/Connect/Disconnect есть. Rename, подтверждённый sensitive export, meta preview, menu bar, понятные все состояния и визуальная проверка нужны. |
| Network change / sleep-wake / reconnect / captive portal | Не реализованы. Нужны bounded backoff, explicit stop/recovery и запрет автоматического обхода защиты. |
| GUI install/uninstall/manual signed upgrade | Research fresh CLI installer доказан; GUI installer, trusted helper install, GUI uninstaller, compatible upgrade/downgrade checks и rollback отсутствуют. |
| Developer ID / packaging / quarantine / notarization | Только ad-hoc components + unsigned pkg. Signing identity не предоставлена, платные действия не разрешены. Нужны signed artifacts и clean target GUI install/chain/timestamp tests; bypass не допустим. |
| Acceptance/security/soak/performance | Modern native loops/DNS/crash + Go checks имеются. Нужны полный matrix по §§16–18 ТЗ, injection после каждого шага, foreign settings/states, hour soak/sleep/reboot/FD/process/PF growth и измерение на старом Intel Mac. |
| Инструкция/лицензии/source/checksums/known limits | Лицензии dependencies и source/checksum reports сохранены. Own-code license ещё не выбрана. Финальная GUI инструкция и список acceptance evidence возможны только после фактического завершения. |

Нельзя закрывать цель на основании одного зелёного CI или сокращать её до split client. Обновлять этот список по фактическому состоянию кода и доказательствам. Непроверенный пункт означает, что программа ещё не готова.
