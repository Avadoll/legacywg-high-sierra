# Native feasibility build result

7 октября 2026: [CI run 37611365955](https://github.com/Avadoll/legacywg-high-sierra/actions/runs/37611365955) завершён успешно. Binary source commit: `7ec2ff8affa5604e9403d26973600f279a53f044`.

Host: Intel macOS 15.7.9 / build 24G830; image 20260824.0482.1; Xcode 16.4 / 16F6; SDK 15.5; pinned official Go 1.24.13. AppKit deployment target 10.13; bundle minimum 10.13.6.

Фактически прошли native сборка обоих неизменённых официальных engine, production core tests, AppKit compilation, component/bundle signature integrity verification, запуск обоих engine через `--version`, test ZIP/DMG packaging и отдельный root probe utun/device/UDP/UAPI Up/Down/Close (104 ms). Root probe исполнялся только на disposable CI host и не менял системные DNS/маршруты/PF. GUI window человеком не проверен; self-test запускает executable без окна.

Подпись только **ad-hoc**: `signed_for_distribution=false`, `vpn_ready=false`. Это диагностическое приложение, не готовый VPN-клиент или доверенный пользовательский установщик. Developer ID/notarization/quarantine install, исполнение на High Sierra, helper authentication, handshake с peer, маршруты/DNS/PF и проверки утечек остаются NOT_RUN. Не отключайте Gatekeeper/SIP/quarantine.

Контрольные суммы после скачивания сверены с CI manifest и содержимым ZIP:

| Тестовый файл | SHA256 |
| --- | --- |
| LegacyWGPlatformProbe-test.zip | `83ea191ca04ea03f41ba0eb6dbef3b0d496d910722912311fff65b50876f7bd4` |
| LegacyWGPlatformProbe-test.dmg | `1da14609e724ac4dd1b7d3824fd8ec434cc5a3dea945b99a524d6dcf27db1b6b` |

CI artifacts хранятся 3 дня. Первый run 37611045729 остановился из-за numeric 0 вместо JSON boolean false в поле target_high_sierra после успешной native compilation/self-test. Исправление явного boolean вошло в указанный binary source commit; повторный run прошёл.
