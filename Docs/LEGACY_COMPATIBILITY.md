# Target compatibility: reference evidence

13 октября статически исследован опубликованный MacPorts wireguard-go 0.0.20250522 package для Darwin 17/x86_64. Архив не установлен и бинарник не запускался. Package signature NOT_VERIFIED; это reference-only, не новая runtime dependency. Build info: Go 1.24.3, CGO_ENABLED=1, x/crypto 0.37.0, x/net 0.39.0, x/sys 0.32.0; у нашего worker Go 1.24.13/CGO0. Полный Mach-O/import comparison и measured SHA256 сохранены в Evidence/Compatibility. Четыре worker imports отсутствуют в reference: _exit, _faccessat, _geteuid, _sendfile; этот список сам по себе не доказывает отсутствие API на target.

[MacPorts source at pinned commit](https://github.com/macports/macports-ports/blob/7c220a7413aef99cd30f8aa88241a85f798d856b/_resources/port1.0/group/go_toolchain-1.0.tcl) описывает опубликованный опыт Go 1.24 на 10.13 и объясняет различие supported OS/minos/реальной загрузки. [Darwin-17 package index](https://packages.macports.org/wireguard-go/) подтверждает наличие пакета. Это сведения сопровождающего проекта, не успешный runtime/VPN test нашего приложения.

Actual High Sierra загрузка, utun/DNS/UDP/routing/Mach/Keychain/GUI/installer, сопровождение EOL Go и Developer ID остаются открытыми. Mach-O metadata не изменялась; архив MacPorts не включается в app/source package и пользователю не предлагается установка MacPorts.
