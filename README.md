# LegacyWG experimental client

Этот репозиторий содержит диагностический этап разработки WireGuard-клиента для Intel macOS 10.13.6. **Полного готового продукта здесь пока нет.**

Приложение `LegacyWGPlatformProbe` проверяет целостность bundle и запуск двух встроенных официальных engine через фиксированный `--version`. Оно не принимает VPN-ключи, не включает туннель, не меняет DNS/маршруты/firewall и не устанавливает root helper. Результат можно сохранить через GUI; автоматической отправки данных нет.

Workflow запускается вручную: Actions → macOS feasibility build → Run workflow. Используется standard runner `macos-15-intel`, scoped Xcode 16.4 / SDK 15.5 и официальный Go 1.24.13 с проверкой SHA256. На private repository до запуска необходимо подтвердить отсутствие оплачиваемого расходования. Создание public repository требует разрешения владельца исходников.

Артефакты — исследовательские `.zip`/`.dmg`, source commit/SHA256 и фактические CI-логи. По умолчанию используется ad-hoc подпись: это не Developer ID поставка. Не отключайте Gatekeeper/SIP/quarantine. Для передачи обычному пользователю требуется согласованный доверенный signing path.

Проверки на современном CI host не доказывают работу на High Sierra. Native encrypted peer, helper authentication, split routes и research package installation проверяются workflow. Target runtime, существующий пользовательский сервер, full tunnel/DNS/IPv6/kill switch, Installer GUI и доверенная поставка остаются непроверенными или не реализованы.

Upstream WireGuard закреплён в `deps.lock.json`, без собственных изменений криптографии. Лицензии сторонних компонентов сохранены в `Vendor` и `Licenses`; см. `THIRD_PARTY_NOTICES.md`. Это собственный проект LegacyWG, не официальное приложение WireGuard. Лицензия собственного кода ещё не выбрана.

Исходное пользовательское ТЗ, личные документы, локальные toolchains/cache, реальные конфигурации/ключи и первоначальная история проекта не включены. Этот repository начинается с отдельного проверенного снимка исходников.

Настоящий limited research client уже реализован: AppKit/Keychain, authenticated Mach helper, official worker, IPv4 split без DNS. Native handshake/шифрованный обмен, 20 Connect/Disconnect циклов и crash/route cleanup прошли на macOS 15.7.9. Full tunnel/DNS/IPv6/hostname endpoints пока отвергаются до сетевых изменений. Test pkg реально установлен и удалён только на disposable CI через CLI; root ownership, launchd и доступ установленного GUI к helper прошли. Pkg unsigned, Installer GUI и High Sierra не проверены. Подробности, source commit и SHA256 — [CLIENT_RESEARCH.md](Docs/CLIENT_RESEARCH.md).
