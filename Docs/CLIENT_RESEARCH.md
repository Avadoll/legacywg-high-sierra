# LegacyWG 0.2: исследовательский IPv4/IPv6 split client

Обновлено: 13 октября 2026. Это настоящий ограниченный VPN backend и AppKit окно, **не завершённый продукт по исходному ТЗ**. Реализованы IPv4/IPv6 split tunnel, numeric IPv4/IPv6 endpoints, до четырёх локальных адресов, 64 маршрутов и восьми routed DNS servers. Hostname bootstrap и native encrypted localhost Endpoint прошли проверку; protected DNS reconnect не реализован. Full tunnel, kill switch, обновление и GUI uninstaller не реализованы. Неподдерживаемые сетевые профили отвергаются до создания интерфейса/изменения сети. IPv6 routes требуют локального IPv6 address и MTU ≥1280; DNS из профиля должен покрываться tunnel routes.

## Реальная реализация

- `App`: импорт стандартного `.conf`, список/удаление профилей, кнопки подключения/отключения, фактический handshake и счётчики. Профили с ключами хранятся только в login Keychain; ACL создаётся для собственного приложения. Исходный файл пользователя не удаляется. Другие приложения не добавляются в trusted ACL автоматически.
- `ConfigCore`: тот же production parser и внутренний UAPI writer. Ключи остаются маскированными при форматировании/JSON. Приватный UAPI доступен только внутри official engine process и не выходит в публичный API/логи/argv/files.
- `Shared/LWMach`: inline JSON с жёстким лимитом и kernel audit trailer; проверка `SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit)` и pin code directory hash. Нет проверки identity по переданному PID/UID/Team ID. Ответ проверяется по root EUID и подписи helper.
- `Helper`: root-owned policy, единственный пользовательский tunnel owner, разрешённый активный console user, только health/start/status/stop. Worker и network component проверяются по подписи и root ownership до запуска из фиксированных путей. Нет shell, произвольных команд/путей или raw UAPI в публичном IPC. При отсутствии запросов владельца 15 секунд или выходе worker процесс останавливается.
- `Engine/worker`: узкий bounded pipe protocol, повторный parse/проверка возможностей на root boundary, official unchanged wireguard-go `device/tun/conn`. TUN/UDP и ключи живут в отдельном процессе; core dumps отключены у GUI, helper и worker. Worker пока остаётся root; privilege dropping не заявляется реализованным.
- `Engine/session`: native utun, проверенные canonical IPv4/IPv6 addresses, фиксированные `/sbin/ifconfig`/`route` без shell, только новые interface-bound routes; откат через закрытие собственного native interface. PF/глобальные default routes не изменяются. Проверяется kernel interface index, чтобы не удалять маршруты на заново использованном имени utun.
- `NetworkAgent`: own temporary SystemConfiguration DNS key через public API; persistent preferences/foreign DNS keys не переписываются. Private bounded pipe с numeric servers и kernel interface identity; heartbeat проверяет наличие своей записи. EOF/SIGKILL закрывает owning session и удаляет temporary key. Worker cleanup идемпотентен; потеря DNS-компонента закрывает tunnel и даёт Error. Это routed profile default resolver, не обещание scoped split DNS или глобального запрета физических DNS: foreign domain-specific/multicast resolvers ещё требуют отдельной политики и проверок.
- `Installer`: настоящий test `.pkg` со fixed payload и launchd job. Это unsigned research package, не Developer ID поставка. Upgrade/refusal сценарий реализован только для свежей установки; установка Installer GUI/удаление на пользовательском Mac не проверены.

Обоснование Mach вместо legacy XPC: [Apple DTS](https://developer.apple.com/forums/thread/681053) описывает ограничения безопасной XPC peer validation на старых ОС; нужные публичные API XPC появились позже 10.13. Mach audit trailer устанавливается ядром, см. [Apple XNU](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/ipc/ipc_kmsg.c). Использованы SDK headers/public APIs; Apple sample/чужой helper код не копировался.

## Проверки

[Run 37615651887](https://github.com/Avadoll/legacywg-high-sierra/actions/runs/37615651887), source `421cbbe60ed14e9a79b79f2231251703a2351afe`, прошёл на Intel macOS 15.7.9 / Xcode 16.4 / SDK 15.5 / Go 1.24.13:

- Native compilation app/helper/worker; production tests/vet; bundle/signature integrity и test packaging.
- Keychain: реальная запись/чтение/удаление temporary item собственным приложением. Denial чужому Keychain requester, пользовательские prompts/locked Keychain и update ACL ещё не испытаны.
- IPC: разрешённый подписанный клиент принят; другой бинарник с тем же identifier отклонён; неверная подпись server response отклонена.
- 20 реальных Connect/Disconnect циклов через helper/root worker/native utun. На противоположной стороне используется отдельный unchanged official engine с upstream userspace network stack. Эфемерные test keys генерируются в памяти; это настоящий handshake/шифрованный UDP round-trip, не mock device и не пользовательский сервер.
- SIGKILL helper: EOF private pipe завершает worker, native interface исчезает; helper возвращается через launchd. Отдельная проверка точного восстановления физических маршрутов добавлена в следующий CI run.

Следующий [run 37616871534](https://github.com/Avadoll/legacywg-high-sierra/actions/runs/37616871534), source `50646d8bade5fcb43ea81b78483ddbf2fc62b347`, тоже прошёл: 20 циклов и crash cleanup дополнительно проверяют исходные gateway/interface маршрутов к обоим benchmark адресам. `route_restoration=PASS`.

Последняя версия этапа 7 октября — [run 37620932618](https://github.com/Avadoll/legacywg-high-sierra/actions/runs/37620932618), source `9284ce20ad97e5e9337e46ce001fb3166f89f5fa`. Все предыдущие проверки повторно прошли. Дополнительно unsigned research `.pkg` реально установлен через CLI Installer на одноразовом CI: проверены root ownership/permissions, подписи компонентов, postinstall launchd activation, Keychain и authenticated health request установленного приложения. Другой клиент отклонён production policy, закреплённой за GUI code hash. После проверки удалены только созданные тестом файлы/job/receipt.

Первый прогон Installer завершился ошибкой: `/Applications/LegacyWG.app` отсутствовал после успешного CLI install. Отключена relocation bundle, закреплён фиксированный путь; preinstall теперь отвергает существующие компоненты и другой target volume. Два следующих установочных прогона прошли. Проверка Installer GUI, quarantine и upgrade не подменяется CLI результатом.

Последние артефакты скачаны, SHA256 и внутренний source commit сверены; worker byte-for-byte совпал с просканированным бинарником. Полный цикл из 20 подключений и одного crash scenario занял 10355 ms; это короткий loopback test, не hour soak или измерение производительности пользовательского VPN. Фактические JSON/logs сохранены в `Docs/Evidence/CI/37620932618`.

| Файл | SHA256 |
| --- | --- |
| LegacyWG-research-0.2.pkg | `38731f45e7be879b49ffea7c85e89eb23139b4d05bcba6f3facad00e911eb230` |
| LegacyWG-research-0.2-app.zip | `d17902f233ad23797e67d9a3743aab6cff105fe082408f0ac6835b3cf4685a39` |

Бинарник worker SHA256 `98f8a7266b4fc959269ce08f23210fca52acc88983126a0d1106cc97df9d6183`. Binary и Darwin source call-graph govulncheck v1.8.0 не оставили unreviewed symbol-level findings. Все module/version findings и узкое Darwin исключение Windows-only GO-2026-4971 сохранены в `Docs/Evidence/ClientSecurity`. Это ограниченный анализ Go; он не аудирует ObjC, installer, ОС или все пути атаки.

## Границы выпуска

Собраны `.app`, app ZIP и unsigned research `.pkg`. Суммы скачанных файлов сверены с CI manifest. Не устанавливать этот пакет на чужой Mac как готовый безопасный продукт; не отключать Gatekeeper/SIP/quarantine. GUI window человеком не проверен. Сам `.pkg` установлен/удалён только на disposable CI host через CLI; через Installer GUI и на High Sierra он не проверен.

**High Sierra 10.13.6, существующий VPN server, доверенная подпись/цепочка/timestamp, полный набор acceptance tests остаются NOT_RUN.** Go worker по-прежнему имеет minos 11.0 из официального linker; метаданные не исправлялись. До подтверждения target runtime нельзя объявлять совместимость. Действующий Developer ID Application ещё не предоставлен; платные услуги/новые аккаунты не создавались.

Остаются обязательными full tunnel, проверенная fail-closed/IPv6 block policy, endpoint routing/bootstrap DNS, recovery journal, GUI uninstall/update, sleep/network/reconnect/soak и target/signing tests. Исследовательская версия не подменяет эти функции. Полный перечень — `READINESS.md`.

## Возобновление 13 октября

[Run 38399327923](https://github.com/Avadoll/legacywg-high-sierra/actions/runs/38399327923), source `fc600f40c34fdf4e594e4cc33e7972b356ed5630`: real OS getaddrinfo получил controlled answer через tunnel по UDP DNS и TCP DNS после truncated UDP response. Disconnect/helper SIGKILL/network agent SIGKILL очистили own resolver; foreign service/global DNS snapshots после каждой проверки совпали с исходными. Полные логи сохранены; никаких пользовательских ключей/серверов не использовалось.

[Run 38400377734](https://github.com/Avadoll/legacywg-high-sierra/actions/runs/38400377734) дополнительно подтвердил refusal подменённого network component с тем же identifier; original signed component восстановлен в finally, после чего normal peer tests снова прошли.

Последняя проверенная сборка — [run 38401449000](https://github.com/Avadoll/legacywg-high-sierra/actions/runs/38401449000), source `3b4a8bcd748d295462633c8e02cb14a03f787542`. Все предыдущие tests/Installer прошли; дополнительно доказаны IPv6 encrypted round trip, numeric IPv6 Endpoint, IPv6 DNS transport UDP/TCP и одновременно IPv4+IPv6 через одну session. Первый IPv6 test остановился на baseline route capture: Darwin route сообщил отсутствие маршрута через stderr с zero exit. Проверка теперь сохраняет diagnostics и различает подтверждённое отсутствие route; неизвестный результат остаётся failure. После disconnect проверяется то же исходное отсутствие или exact gateway/interface.

Скачанные app/pkg SHA256 и embedded commit сверены. Worker SHA256 `7e6522dfb81292bbfbddca7486bf242a83f7b1f611ad01925aaf150abac9af71` повторно проверен govulncheck v1.8.0 13 октября: 88 binary / 91 source findings; unreviewed symbol-level findings отсутствуют после прежнего узкого Darwin исключения Windows-only GO-2026-4971. Все findings сохранены в `Evidence/ClientSecurity/2026-10-13-DualStack`. Это ограниченный Go analysis, не полный аудит и не решение EOL OS/toolchain.

| Последний файл | SHA256 |
| --- | --- |
| LegacyWG-research-0.2.pkg | `7383e7890f7a56b9a1b26134d013373fe31f642113d4cb34f4e3ef7551b34efa` |
| LegacyWG-research-0.2-app.zip | `812dfa60cb49f231a6ac80dbe230339aaac4e79194e2fd94ac65e4e4d40cd98c` |

Baseline tag signature теперь проверена по ключу `AB9942E6D4A4CFC3412620A749FC7012A5DE03AE`, опубликованному [сопровождающим](https://www.zx2c4.com/). Raw tag/key/log сохранены в `Evidence/SourceTrust`. Новый candidate commit `2631ce9…` unsigned и не покрывается старой tag signature; Web of Trust не заявляется. High Sierra/Developer ID/quarantine/существующий сервер по-прежнему NOT_RUN.


## Промежуточная GUI сборка 13 октября

Native run [38412666208](https://github.com/Avadoll/legacywg-high-sierra/actions/runs/38412666208), source `7284de0054976f2053c65e00e5e1f5a725e00900`: bounded hostname bootstrap/encrypted localhost, два независимых encrypted peers и отдельная статистика, IPv4/IPv6/dual-stack, real DNS UDP/TCP/crash restoration, signed-component authentication, Keychain, fresh research installer прошли. GUI: menu bar/close-window policy, handshake date, profile label rename with unchanged ID/data, unsafe label refusal и sanitized diagnostic preview/export. Native Aqua fixture inspected: labels/controls читаемы; pixel check предотвращает прежний пустой label capture. Fixture не является проверкой реальных modal/menu clicks, accessibility, target OS или VPN.

Root worker byte-identical to reviewed PeerStatus scan: `9e68650c7914d1d512e4f4767906328f3789d487815217d7c61e3c216040ce3a`. 124-file production Go source identity также совпала; explicit reuse evidence сохранено. Это ограниченный Go analysis, не аудит изменённого Objective-C. Actual High Sierra, Developer ID, existing user server, full tunnel и kill switch не доказаны. Матрица незавершённого полного объёма — READINESS.md.

Latest research artifacts (ad-hoc components / unsigned pkg, release_approved=false):

| Файл | SHA256 |
| --- | --- |
| `LegacyWG-research-0.2.pkg` | `07bb6b421cbc6d57a5ed0d4bb5c67294a4262a771028e9079a9b933a8b00054a` |
| `LegacyWG-research-0.2-app.zip` | `d1e1fe756426c0b6bd3f0e84ad1bda591a8ecd81f453ffa9894b0b3ae52cadcb` |

## Текущая проверенная сборка

Native [run 38419688718](https://github.com/Avadoll/legacywg-high-sierra/actions/runs/38419688718), source `90efb8b8583422f857d8b1054299b2493babb0cf`: прежние IPv4/IPv6/dual-stack/DNS/crash/hostname/multi-peer/auth/Keychain/installer scenarios PASS; real NSApp launch/close-window lifecycle PASS; controlled endpoint path loss после настоящего encrypted traffic закрывает worker tunnel/Error с восстановлением own routes. Scope/limits — NETWORK_CHANGE.md. Full tunnel, guard/journal/reconnect/target/signing остаются незавершёнными.

Worker SHA256 `e35a8a25f7c1c0911949fd5ad93d98d86ed0fa691b5c7ec58bd136128a259e9b`; 128-file production Go identity, scoped scanner PASS (90/92 module-level findings, narrow Windows-only exclusions). No independent audit/security approval. Latest downloaded/staged unsigned research artifacts:

| Файл | SHA256 |
| --- | --- |
| `LegacyWG-research-0.2.pkg` | `f3ba3c52cec122ccc317459d5afc8d90dcf39c3625babbfeee37f788f98b589b` |
| `LegacyWG-research-0.2-app.zip` | `fe514cda6242c3d4b85df36d6f2ad28da0a2dfb255d59ff5a7da82d75e3350cd` |
