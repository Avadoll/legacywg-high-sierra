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

## Предыдущая проверенная сборка (route loss)

Native [run 38419688718](https://github.com/Avadoll/legacywg-high-sierra/actions/runs/38419688718), source `90efb8b8583422f857d8b1054299b2493babb0cf`: прежние IPv4/IPv6/dual-stack/DNS/crash/hostname/multi-peer/auth/Keychain/installer scenarios PASS; real NSApp launch/close-window lifecycle PASS; controlled endpoint path loss после настоящего encrypted traffic закрывает worker tunnel/Error с восстановлением own routes. Scope/limits — NETWORK_CHANGE.md. Full tunnel, guard/journal/reconnect/target/signing остаются незавершёнными.

Worker SHA256 `e35a8a25f7c1c0911949fd5ad93d98d86ed0fa691b5c7ec58bd136128a259e9b`; 128-file production Go identity, scoped scanner PASS (90/92 module-level findings, narrow Windows-only exclusions). No independent audit/security approval. Latest downloaded/staged unsigned research artifacts:

| Файл | SHA256 |
| --- | --- |
| `LegacyWG-research-0.2.pkg` | `f3ba3c52cec122ccc317459d5afc8d90dcf39c3625babbfeee37f788f98b589b` |
| `LegacyWG-research-0.2-app.zip` | `fe514cda6242c3d4b85df36d6f2ad28da0a2dfb255d59ff5a7da82d75e3350cd` |

## Предыдущая проверенная сборка (utun journal)

Native [run 38428112392](https://github.com/Avadoll/legacywg-high-sierra/actions/runs/38428112392), source `4600283770206273c9ded5acb960d3131ca491a9`: root-only typed journal с native FD metadata/ACL checks, exclusive lock, canonical bounded records, foreign/reused identity refusal и five SIGKILL checkpoints PASS. Все прежние encrypted peers/20 cycles/DNS/helper crash/path loss/GUI lifecycle/fresh unsigned installer scenarios PASS на Intel macOS15.7.9. Схема охватывает только utun/DNS; physical route/PF journal, GUI/startup recovery, full tunnel, protection, target/signing остаются незавершёнными.

Worker SHA256 `0a41089d252ac766e4842946e97d6cf5a127e805711d9c7b9f70722b5ee0fda7`; 132-file production Go identity, новый binary/source scoped scanner PASS (90/92 findings, только documented Windows-only GO-2026-4971 exclusions). Это не независимый аудит Objective-C, root installation или High Sierra.

| Файл | SHA256 |
| --- | --- |
| `LegacyWG-research-0.2.pkg` | `7d0fbe257a30638b5b9d2ebe518fbb9a9fd0d57c9b6553229d2eb94122f06fab` |
| `LegacyWG-research-0.2-app.zip` | `885b43d761f965af41ed8add665d6b789554e73265884a972663c0be29ffbcee` |


## Предыдущая проверенная сборка (startup / Recover)

Native [run 38431568914](https://github.com/Avadoll/legacywg-high-sierra/actions/runs/38431568914), source `13cd2733631413af05f47f545d9c991c7cc10eeb`: actual authenticated startup/Recover/Stop/Start scenarios PASS на Intel macOS15.7.9. Corrupt journal вызывает RecoveryRequired; все операции сохраняют неоднозначную запись и fixed error. Clean recovery идемпотентен и не создаёт connection intent/utun; подтверждённо stale собственная запись удаляется при startup. Recover при активном VPN отклоняется, после чего настоящий encrypted round trip продолжает работать. Unauthorized Recover отказан. Шесть required root tests и пять actual SIGKILL checkpoints PASS; прежние 20 encrypted cycles/DNS/crash/path-loss/installer regression PASS. High Sierra/reboot/power loss/physical routes/PF — NOT_RUN.

Worker SHA256 `8f6a6a93bb27023d0424aa8c0585c260079ae36761bcde2b1f33b02554a54d3c`; scoped Go binary/source analysis PASS, 132-file identity `e7ae54962fc015285427086f8b57fd1440892eb4cc5b7942943d383c4fc884fc`. Unknown-state/recovery GUI fixture and readable Aqua screenshot PASS; actual modal actions NOT_RUN. Ad-hoc components/unsigned pkg, release_approved=false.

| Файл | SHA256 |
| --- | --- |
| `LegacyWG-research-0.2.pkg` | `c32540777e70f4ba59d730306e45f0ef4d13998a156bcdb4267d780a573079a4` |
| `LegacyWG-research-0.2-app.zip` | `8cb236c8fc9008ea4b1da20453506dd74831bbb10f9c5db924ee4e016289e679` |


## Предыдущая проверенная сборка (duplicate import / profile sheets)

[Run 38443154396](https://github.com/Avadoll/legacywg-high-sierra/actions/runs/38443154396), source `8eb32ec556c5b055650fb8624cd4ff07d45ef450`, Intel macOS15.7.9/Xcode16.4/SDK15.5: native build/self-tests/actual profile sheets и прежние encrypted peer/DNS/crash/recovery/20-cycle/fresh installer tests PASS. Keychain name/exact-data conflict detection, exact item replacement preserving ID/label and unrelated item, oversized/missing item/duplicate name refusal, actual invalid worker validation PASS. Developer UI fixture открывает настоящий delete sheet, блокирует Connect/Quit во время него, меняет simulated status на Connecting перед подтверждением и проверяет сохранение Keychain data; duplicate→new-name sheet→Cancel также сохраняет fixture data. Это controller/Keychain modal proof с simulated status, не active encrypted VPN/long-modal heartbeat test и не actual file-picker/typed-copy/replacement button end-to-end acceptance. Aqua layout inspected.

Worker byte-identical to RecoveryState scoped scan; receipt security-byte-identity.json verifies exact binary and source identity, not changed Objective-C security. Components ad-hoc/pkg unsigned, release_approved=false; High Sierra/existing user server/full protection NOT_RUN.

| Файл | SHA256 |
| --- | --- |
| `LegacyWG-research-0.2.pkg` | `13405e7f8e7f28031144095ed321e86765dfdd35d805950a75c10beb9b398675` |
| `LegacyWG-research-0.2-app.zip` | `0738d1113cae60fa30d42bc2ebfd84273488df1c09db47ca2b840738d9bfb378` |

## Предыдущая проверенная сборка (private profile preview / licenses)

[Run38446849175](https://github.com/Avadoll/legacywg-high-sierra/actions/runs/38446849175), source `ec3fc4775e3e8cfd23b2cc8eb545238cced7af7e`, Intel macOS15.7.9/Xcode16.4/SDK15.5: private selected-profile preview and actual About/license sheet PASS. Native CLI validation/metadata formatting, complete bundled license files, actual Keychain selected-profile read/preview, profile delete/changed-state refusal/copy Cancel sheets PASS with eight separate proof booleans. New readable Aqua layout inspected. All previous authenticated encrypted IPv4/IPv6/dual-stack peers, native UDP/TCP DNS, route loss, recovery/crash, 20 cycles, GUI lifecycle and fresh research installer PASS.

Worker SHA256 `250527c8874a451bc86fa92b4d4940ee3cc01bc5b3228198cfef640bcc58f19f`; fresh scoped Go review PASS, source identity `b2071b2b7d111da2e195eba999d48903da5b9f08a0ce424e6b26293bb3e632ff`. Research/ad-hoc components and unsigned pkg, release_approved=false. High Sierra/existing user server/full protection NOT_RUN.

| Файл | SHA256 |
| --- | --- |
| `LegacyWG-research-0.2.pkg` | `3d7902625bb724589d397a1d0a83e7ef3dbe2ca37e72a5f76fddcebc86364d1b` |
| `LegacyWG-research-0.2-app.zip` | `e8c1df6ed058378ff6d24e637eb70071e52c1ab4e3c2a7ac527c6c24e0ae944d` |

## Previous research build / live encrypted GUI sheet

[Run 38450311846](https://github.com/Avadoll/legacywg-high-sierra/actions/runs/38450311846), source `0fb5bbf6e08864844c26b930dfca50c48467cf3c`, Intel macOS15.7.9/Xcode16.4/SDK15.5: настоящий controller приложения наблюдал активный encrypted WireGuard tunnel через authenticated helper. About/license sheet оставался открытым 19.45s (watchdog helper15s); 9 actual Connected replies подтвердили тот же interface. Connect/disconnect/recover/Quit actions при открытом sheet refused; menu controls disabled. После закрытия sheet main window закрыто на5s, timer/app/tunnel remained active (3 replies). Четыре native encrypted UDP round trips прошли во время sheet и hidden window; test coordinator не посылал helper requests в этот интервал. После обычного Stop проверены исчезновение interface и restoration исходных route gateway/interface.

- `LegacyWG-research-0.2.pkg` SHA256 `90560ad110c4479d476e85c2ee8fa9f362dc883fc0f5a44ee7607730641d841a`
- `LegacyWG-research-0.2-app.zip` SHA256 `3316bf05ba0b9b03887ebfd0dff439b94eb6e023b703c9fe7ef5b55bbf9f7aaa`

Worker unchanged: `250527c8874a451bc86fa92b4d4940ee3cc01bc5b3228198cfef640bcc58f19f`. Exact132-file production Go identity `b2071b2b7d111da2e195eba999d48903da5b9f08a0ce424e6b26293bb3e632ff` совпадает с fresh ProfilePreview scan source `ec3fc4775e3e8cfd23b2cc8eb545238cced7af7e`. Previous scan applies to byte-identical worker; no changed production Go/ObjC code in this checkpoint. New developer tests/build orchestration were reviewed separately; this does not expand the Go scan into a complete security audit.

Это отдельный developer test executable с exact included App/main.m и subclass, считающим реальные replies; runtime state не подменяется. Clone собран ПОСЛЕ app ZIP/pkg: test executable и временная OR-policy двух точных cdhash не входят в installer. Ordinary production app/helper policy остались прежними. Test opens sheet/controller actions programmatically; это не mouse/accessibility/menu-tracking acceptance. Long runModal Quit confirmation/accepted async Quit, GUI SIGKILL/heartbeat-loss negative control, actual recovery/file-picker/typed-copy/replacement, locked/foreign Keychain и High Sierra ещё не проверены. Внешний сервер/полная защита/подписанная поставка остаются открытыми.

## Current research build / Quit and GUI crash

[Run 38451987993](https://github.com/Avadoll/legacywg-high-sierra/actions/runs/38451987993), source `d32a5a5e114d648386c635b53cae4b0ba1461b7f`, Intel macOS15.7.9/Xcode16.4/SDK15.5: actual AppKit terminate event entered production nested runModal Quit confirmation for19.97s; 10 authenticated Connected replies and3 encrypted echoes passed. Cancel leaves app/timer/tunnel active. Accepted Quit produces real applicationWillTerminate only after authenticated Stop acknowledgement/timer invalidation; post-exit status was Disconnected and own interface/routes restored BEFORE coordinator Stop. Actual SIGKILL while About sheet/real DNS-enabled tunnel active caused helper watchdog cleanup in14311ms after kill, with0 coordinator helper requests: own interface gone, Disconnected, DNS own key gone and baseline foreign resolver digest/count restored. Encrypted echo during2s watchdog grace passed.

- `LegacyWG-research-0.2.pkg` SHA256 `67e2987653d56ce34f37a89d0368af90f0dbed05caf348effc8eced336cda5d4`
- `LegacyWG-research-0.2-app.zip` SHA256 `9f338c993f5067050573587c57d4ad1170afd410b2f899c19150d0e0afdb6eaa`

Worker unchanged `250527c8874a451bc86fa92b4d4940ee3cc01bc5b3228198cfef640bcc58f19f`; exact132-file production source identity `b2071b2b7d111da2e195eba999d48903da5b9f08a0ce424e6b26293bb3e632ff`. Retained fresh ProfilePreview scan by exact byte/source receipt; no changed product Go/ObjC logic. This is not an audit of all Objective-C/root/install/target attack paths.

Developer-only separate test bundle includes exact production App/main.m; subclass records replies/termination notification and custom AppKit event invokes terminate:. Nested runModal is entered outside a main GCD callback; no runtime status simulation, watchdog threshold or product timer changes. Cancellation/acceptance uses programmatic stopModalWithCode; actual mouse/keyboard/accessibility/menu tracking remain untested. Ordinary ZIP/pkg were created before test clone and contain neither its observer classes nor the temporary two-exact-cdhash test policy. Prior long About/hidden-window/20cycles/peer/DNS/journal/crash/recovery/UI/fresh installer regressions PASS.

Current unprotected split-tunnel watchdog restores ordinary internet after GUI loss. It is NOT immediate fail-closed and does not preserve a protected state: product PF guard is not implemented and full profiles remain rejected. These tests must not close the full protected GUI-crash requirement. High Sierra/external authorized server/signed distribution, real recovery dialogs/error Quit/locked Keychain/file-picker/typed-copy/replacement/drag-and-drop/reconnect/sleep remain open.

Latest native client run38464390218/source583c17f476858d22e8361fc0a809371b849a48a0: production current official endpoint sampler implemented, same-path numeric roaming/new-address path checks/overlap/own-utun refusal and unique RTM_GET sequences added. Native policy tests/helper encrypted/DNS/GUI/recovery/installer regressions PASS; new worker binary/source Go review PASS. No public endpoint metadata, full/PF/scoped transport/signing/High Sierra claim. Research app/pkg updated with verified hashes; ad-hoc components/unsigned installer remain research only. Full authenticated roaming/new-destination route-loss e2e and physical/protected reconnect acceptance still open.

Run38468237984/sourceda65e6f682ffe7335b7d6ff88245134c4a729844: actual installed helper IPv4 authenticated endpoint IP+port roaming remained encrypted/Connected beyond2monitor polls; changing only the new destination route while old path/outer interface stayed valid caused actual Error/inner cleanup before coordinator Stop in1960ms. Four echoes and route/interface restoration PASS, prior native regressions retained. Test code only; worker byte/source identity permits the exact earlier CurrentEndpoints Go review. App/pkg refreshed with verified hashes, still unsigned research/target/PF/physical/IPv6 roaming gates open.

## Native IPv4/IPv6 current-endpoint integration

Run38469783940/source7c24f239af446b350707e518cdb9a8e834577e05: actual authenticated production helper current-endpoint roaming/new-destination-only route loss now PASS for IPv4 and IPv6 separately. Each:4 unique encrypted echoes/Connected beyond2monitor ticks, same official peer rebinds numeric IP+port; old route unchanged/outer UP while only new destination redirected. Worker Error/inner interface+route baseline restoration before coordinator Stop, observed1946ms v4/1958ms v6. Outer baselines/interface set restored; original missing IPv6 route preserved if baseline absent. Immutable per-fixture family parameters, no process-wide mutable address switch; bounded ephemeral-key pipe/45s child lease/core dumps off. All previous native helper/GUI/DNS/20cycle/recovery/installer checks retained. Developer fixture excluded from pkg; production134-file Go identity and worker bytes unchanged, exact CurrentEndpoints scan reuse receipt. App/pkg reverified/staged. These single-run timings are not worst-case or fail-closed packet guarantees. Physical/scoped-default/gateway/index-generation/cross-family/hostname/sleep/protected PF admission/full/High Sierra/trusted signing remain open.

Latest native run38472898459/source021d99033370110dea1ce8da0c2e998d65578b22: canonical PF metadata/durable root writer/four SIGKILL preservation tests added. Ordinary recovery refuses unresolved PF documents; no guard activation/kernel release/automatic PF undo is exposed. Full native GUI/helper/installer tests and new worker Go review passed. UI self-test now drains the actual initial asynchronous status request before controlled fixtures; normal GUI logic unchanged. Research app/pkg reverified and staged, full/physical/target/trusted distribution still incomplete.

Latest run38474823221/sourcec8667acfcf3d0181f49835b751de1a301c20e228: PF metadata v2 pre-reference cancellation and old/pending rule generations now have durable root tests/eight actual SIGKILL preservation points. No kernel guard or reference/rule automatic undo. New worker source/binary Go review and all native client regressions PASS; research app/pkg reverified/staged. Complete PF effect coordinator/physical/full/target/signing remain required.


Latest source `dc6272cc5b4376d8801ddf59d19c3457f87a66ec`: PF anchor-effect run38477880009 PASS, real disabled-PF journal-bound own load/cancellation/fourSIGKILL/dead-owner recovery and changed-rule/boot refusal/post-finalizer absence. Coordinator remains private/not client-activated, no references or packet guard. Full client run38477886003 and fresh 142-file worker Go review PASS; verified research artifacts staged. Atomic privileged concurrency/all kernel anchors/physical/full/target/signing remain open; protection_ready=false. See PF_RESEARCH.md for failed/predecessor evidence and exact limits.


Latest native reference/anchor source `cbe66c0152d51e74e96f81ae3538bfa3c6268f45`: reference run38481109825 PASS8actualSIGKILL, concurrent acquire→one reference, actual lost-token/confirmed release recovery, pre-acquire cancellation and other PID/reference preservation; disabled-anchor run38481064418 PASS4actualSIGKILL. New private kernel coordinator exists and shared Store mutex covers ordinary lifecycle/Close. Client PF activation/recovery/protection is not enabled. Unsupported private ABI/no atomic compare-release/all kernel anchors/foreign ordering/state policy/physical/full/protected crash/target/signing remain open. Full client run38481414640 and fresh 147-file worker Go review PASS; research artifacts verified/staged, vpn_ready=false. See PF_RESEARCH.md for exact evidence, limits and eight checkpoints.


Latest `be6643a42e3db2a21713f4cb66bbd0b6ad3bfccb`: native typed-rule run38485071832 PASS3SIGKILL/actual old-hash rollback/new-hash confirmation, numeric v4/v6 UDP+loopback+journal-owned utun policies, path refusals/no-op, pre-load cancellation and unknown-third-hash preservation/post-finalizer cleanup. Reference run38485075643 PASS8SIGKILL and full client run38485079424/fresh 151-file worker Go review PASS; research app/pkg verified/staged. Dynamic private guard backend exists, but installed client protection/full routes remain disabled. Actual packet/physical/scoped path/all kernel anchors/foreign state and ordering/protected crash/reconnect/target/signing gates open. See PF_RESEARCH.md for exact scope.


Current WIP source `28f159a643bcc21a4c26f6e5c45031283fa32020` / native run38492284213 **FAIL**: bounded direct PF kernel-tree reader detects nested quick/NAT policy, but exact namespace cleanup fails. Empty single-class transaction restores baseline; multi-class leaves a node. Cleanup now preserves ownership journal until actual node absence. Earlier rule/hash/reference PASS did not prove namespace retirement. Invalid C-ABI run38492051583 is rejected and corrected; see PF_RESEARCH.md. No new app/package/scan; staged be6643a/run38485079424 remains split-only unsigned research. Full product and goal incomplete.


Standalone source `d49b20be0097171b65b060d4f481c4964ec84845` / run38495436572 PASS: singleton fixed deny/lo0 rule loads, exact namespace cleanup across3cycles and3actual SIGKILL; full3104-byte Go codec equality to compiled primary C structs for deny/lo0/UDP4/UDP6. Full coordinator suite NOT_RUN; its existing strict namespace-retirement FAIL remains open. Shared PF pool staging/private ABI are not atomic/supported product guarantees. Pure Go codec exists but no new kernel loader/client guard integration or package/scan. Staged be6643a/run38485079424 remains split-only unsigned research. Full scope and goal incomplete; PF_RESEARCH.md records next concrete integration step.


Latest source `26d5903377af46ca37b19f13f1f4ae904f7082c2`: full PF rule run38499210383 PASS6update+6stage/removal SIGKILL, journal-bound singleton Go loader, exact namespace retirement and nested foreign quick/NAT refusal/restore. Reference run38499353808 PASS8SIGKILL/other owner preserved. Full client run38499597316 and fresh 159-file worker review PASS; research artifacts verified/staged. Guard APIs remain private/unactivated; full profiles rejected. Shared pool/private ABI/privileged atomicity/physical routes/protected packets/reconnect/sleep/GUI/target/signing/full acceptance open. PF_RESEARCH.md records exact scope; goal incomplete.


Latest packet checkpoint: source `7c0adcb679391e8be25cb877201f5b927a372778` / full PF run38502471592 PASS native owned-utun IPv4/IPv6 UDP/TCP/DNS port tests and actual owner SIGKILL persistent denial; full client run38502474171 and fresh160-file Go review PASS. Research artifacts staged; guard unactivated/full profiles rejected. Connected Go UDP/Go resolver issue remains OPEN. Next: official encrypted synthetic packet tests, then physical path/route/installed guard/full original acceptance. See PF_RESEARCH.md for precise scope. Product incomplete.


Latest encrypted packet checkpoint: full PF run38609111273/source`118da12c1c078dd947eefb9075298ca73e2f6292` PASS official StdNetBind, synthetic outer4/outer6, inner dual-stack UDP/TCP/DNS-format exchange and independent outer/inner exception removal; prior SIGKILL/namespace/foreign-tree regressions retained. Full client run38608920722/source`4341a099ef27a687f216abc40e565868f2a5d82e` and fresh161-file Go review PASS; Go identity with PF suite separately verified. Unsigned split-only research app/pkg staged, installed guard remains disabled. See PF_RESEARCH.md for scope. Next: encrypted owner SIGKILL, physical scoped lifetime/owned routes and full original target/trust/acceptance. Product incomplete.


Latest encrypted crash checkpoint: full PF run38612559239/source`fb70c4dd2a9b0cd2709622e27eb45cab2b7d7cfe` PASS two real encrypted guard-owner SIGKILL cases with native WaitStatus proof, persistent dual-stack UDP/TCP/DNS-format denial, explicit recovery and exact PF baseline. Prior generation/namespace/foreign-tree/plaintext regressions retained. Fresh current161-file Go review PASS; existing client4341a09/run38608920722 retained with exact351-file nonchanged source identity (enumerated test/docs exclusions). No new app/pkg, installed guard remains disabled/full profiles rejected. Next: nonprivileged outer escape negative control/root-UID candidate, then physical lifetime/owned routes/installed guard/full original acceptance. See PF_RESEARCH.md; product incomplete.


Latest root-socket checkpoint: full PF run38616086488/source`92bb44033b09b3534657f682bd5950ddb1878bac` PASS fixed UID0 typed UDP escapes, ordinary-process positive baseline/tunnel permission and outer-UDP refusal for IPv4/IPv6, official encrypted/SIGKILL/foreign-tree/namespace regressions and complete primary-C codec comparison. New full client run38616094367 and fresh162-file Go review PASS; research artifacts verified/staged. Installed guard remains disabled/full profiles rejected. Other-root/source-port/socket/physical lifetime and all original target/trust/acceptance remain open; old wider private policy is retained/refused, no migration claimed. Next: actual worker source-port/socket admission, then physical owned routes/full installed protection. See PF_RESEARCH.md; product incomplete.


Latest 2026-10-22 source-port checkpoint: full PF run39791914031 and full client run39791920805, source `924f033c633335903cc3e6ab96749bc2a907f575`, PASS. Exact actual source-port policy, wrong-port root rejection, matching-port ordinary-UID rejection, explicit encrypted revoke/Down/reopen/re-admit and prior crash/namespace regressions verified. Fresh 162-file Go review and artifact source/checksum verification PASS. Installed guard remains unactivated/full profiles rejected. Automatic socket lifetime controller is next, followed by physical owned routes/full protection and all original target/trust/acceptance gates. See PF_RESEARCH.md. Product incomplete.


Latest automatic transport checkpoint (2026-10-22): source `5c195f023f151ebfffb9cf00671640eb1b58f78d`, focused39796023465/full PF39797557322/client39796027645 PASS. Native private Bind confirms deny-only before socket release, retains uncertain ports with Store/global GC pins, explicitly reconciles pending effects, and passes official encrypted Down/Up/Close for both outer families. Native deadline/port/old-callback/third-hash/GC checks and bounded-send lock-order model PASS; prior crash/namespace regressions retained. Fresh 166-file Go review and new research artifact verification PASS. Installed guard remains unactivated/full profiles rejected. Next: physical scoped endpoint/durable route ownership, then installed guard/state/recovery integration and all original target/trust/acceptance gates. See PF_RESEARCH.md. Product incomplete.
