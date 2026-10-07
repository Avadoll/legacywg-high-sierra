# LegacyWG 0.2: исследовательский IPv4 split client

Дата: 7 октября 2026. Это настоящий ограниченный VPN backend и AppKit окно, **не завершённый продукт по исходному ТЗ**. В этой версии реализованы только IPv4 split tunnel, numeric IPv4 Endpoint, до четырёх локальных адресов и 64 маршрутов. DNS, IPv6, hostname endpoints, full tunnel, kill switch, обновление и GUI uninstaller не реализованы. Такие сетевые профили отвергаются до создания интерфейса/изменения сети, а не подключаются с ослабленной защитой.

## Реальная реализация

- `App`: импорт стандартного `.conf`, список/удаление профилей, кнопки подключения/отключения, фактический handshake и счётчики. Профили с ключами хранятся только в login Keychain; ACL создаётся для собственного приложения. Исходный файл пользователя не удаляется. Другие приложения не добавляются в trusted ACL автоматически.
- `ConfigCore`: тот же production parser и внутренний UAPI writer. Ключи остаются маскированными при форматировании/JSON. Приватный UAPI доступен только внутри official engine process и не выходит в публичный API/логи/argv/files.
- `Shared/LWMach`: inline JSON с жёстким лимитом и kernel audit trailer; проверка `SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit)` и pin code directory hash. Нет проверки identity по переданному PID/UID/Team ID. Ответ проверяется по root EUID и подписи helper.
- `Helper`: root-owned policy, единственный пользовательский tunnel owner, разрешённый активный console user, только health/start/status/stop. Worker проверяется по подписи и root ownership до запуска из фиксированного пути. Нет shell, произвольных команд/путей или raw UAPI в публичном IPC. При отсутствии запросов владельца 15 секунд или выходе worker процесс останавливается.
- `Engine/worker`: узкий bounded pipe protocol, повторный parse/проверка возможностей на root boundary, official unchanged wireguard-go `device/tun/conn`. TUN/UDP и ключи живут в отдельном процессе; core dumps отключены. Worker пока остаётся root; privilege dropping не заявляется реализованным.
- `Engine/session`: native utun, проверенные canonical addresses, фиксированные `/sbin/ifconfig`/`route` без shell, только новые interface-bound routes; откат через закрытие собственного native interface. DNS/PF/глобальные default routes не изменяются. Проверяется kernel interface index, чтобы не удалять маршруты на заново использованном имени utun.
- `Installer`: настоящий test `.pkg` со fixed payload и launchd job. Это unsigned research package, не Developer ID поставка. Upgrade/refusal сценарий реализован только для свежей установки; установка Installer GUI/удаление на пользовательском Mac не проверены.

Обоснование Mach вместо legacy XPC: [Apple DTS](https://developer.apple.com/forums/thread/681053) описывает ограничения безопасной XPC peer validation на старых ОС; нужные публичные API XPC появились позже 10.13. Mach audit trailer устанавливается ядром, см. [Apple XNU](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/ipc/ipc_kmsg.c). Использованы SDK headers/public APIs; Apple sample/чужой helper код не копировался.

## Проверки

[Run 37615651887](https://github.com/Avadoll/legacywg-high-sierra/actions/runs/37615651887), source `421cbbe60ed14e9a79b79f2231251703a2351afe`, прошёл на Intel macOS 15.7.9 / Xcode 16.4 / SDK 15.5 / Go 1.24.13:

- Native compilation app/helper/worker; production tests/vet; bundle/signature integrity и test packaging.
- Keychain: реальная запись/чтение/удаление temporary item собственным приложением. Denial чужому Keychain requester, пользовательские prompts/locked Keychain и update ACL ещё не испытаны.
- IPC: разрешённый подписанный клиент принят; другой бинарник с тем же identifier отклонён; неверная подпись server response отклонена.
- 20 реальных Connect/Disconnect циклов через helper/root worker/native utun. На противоположной стороне используется отдельный unchanged official engine с upstream userspace network stack. Эфемерные test keys генерируются в памяти; это настоящий handshake/шифрованный UDP round-trip, не mock device и не пользовательский сервер.
- SIGKILL helper: EOF private pipe завершает worker, native interface исчезает; helper возвращается через launchd. Отдельная проверка точного восстановления физических маршрутов добавлена в следующий CI run.

Следующий [run 37616871534](https://github.com/Avadoll/legacywg-high-sierra/actions/runs/37616871534), source `50646d8bade5fcb43ea81b78483ddbf2fc62b347`, тоже прошёл: 20 циклов и crash cleanup теперь дополнительно проверяют исходные gateway/interface маршрутов к обоим benchmark адресам. `route_restoration=PASS`. Это последняя собранная research версия; production worker код не менялся относительно проверенного анализатором бинарника.

Последние артефакты скачаны, SHA256 и внутренний source commit сверены; worker byte-for-byte совпал с просканированным бинарником. Полный цикл из 20 подключений и одного crash scenario занял 10461 ms; это короткий loopback test, не hour soak или измерение производительности пользовательского VPN.

| Файл | SHA256 |
| --- | --- |
| LegacyWG-research-0.2.pkg | `27076115a613299985f61a3c2413321d7775819710cd058f9ea4472b480afb31` |
| LegacyWG-research-0.2-app.zip | `513781832216a9d8ae102cf37eeb9e27b776c92815afd52051991526d682c259` |

Бинарник worker SHA256 `98f8a7266b4fc959269ce08f23210fca52acc88983126a0d1106cc97df9d6183`. Binary и Darwin source call-graph govulncheck v1.8.0 не оставили unreviewed symbol-level findings. Все module/version findings и узкое Darwin исключение Windows-only GO-2026-4971 сохранены в `Docs/Evidence/ClientSecurity`. Это ограниченный анализ Go; он не аудирует ObjC, installer, ОС или все пути атаки.

## Границы выпуска

Собраны `.app`, app ZIP и unsigned research `.pkg`. Суммы скачанных файлов сверены с CI manifest. Не устанавливать этот пакет на чужой Mac как готовый безопасный продукт; не отключать Gatekeeper/SIP/quarantine. GUI window человеком не проверен. Test helper ставился/удалялся только на disposable CI host; сам `.pkg` через Installer GUI не устанавливался.

**High Sierra 10.13.6, существующий VPN server, доверенная подпись/цепочка/timestamp, полный набор acceptance tests остаются NOT_RUN.** Go worker по-прежнему имеет minos 11.0 из официального linker; метаданные не исправлялись. До подтверждения target runtime нельзя объявлять совместимость. Действующий Developer ID Application ещё не предоставлен; платные услуги/новые аккаунты не создавались.

После разрешённого signing/target test необходимы full tunnel, native DNS transaction/recovery, IPv6 policy, endpoint routing/bootstrap DNS, GUI uninstall/update и crash/sleep/network/soak tests. Исследовательская версия не подменяет эти обязательные функции.
