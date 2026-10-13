# Окно и menu bar

Добавлено 13 октября 2026; menu bar/layout run 38407812310 / source ee167e210ed4e6baca682657c70e9f9a41dba3dd прошёл. Rename/diagnostic privacy прошли run 38409629954. Final native-label capture run 38412666208 / source 7284de0054976f2053c65e00e5e1f5a725e00900 inspected: читаемый native Aqua layout fixture. Это не real modal/menu/accessibility/target acceptance.

Закрытие главного окна оставляет приложение и status item работающими. Через menu bar можно открыть окно, увидеть выбранный/активный профиль и состояние, подключить или отключить туннель. Текстовая метка WG совместима с target API, не требует SF Symbols. Точка рядом с WG означает запущенный туннель, а tooltip уточняет handshake/ожидание; это не знак подтверждённого kill switch.

Статус опрашивается асинхронно каждые две секунды в common run-loop modes, чтобы открытое меню не останавливало owner heartbeat. Параллельные запросы и повторные операции подавляются busy/quitting guard. При выполняющейся операции выход отменяется с понятным сообщением.

«Выйти» при активном туннеле предлагает «Отключить и выйти»/«Отмена». Отказ оставляет приложение работающим. Подтверждение запускает Stop асинхронно и использует NSTerminateLater; только положительный ответ аутентифицированного helper разрешает завершение. При отсутствии подтверждения окно остаётся открытым с ошибкой. Продолжение туннеля после Quit пока не реализовано и не предлагается.

Окно показывает tunnel interface, дату последнего handshake, число peers с handshake, реальные суммарные RX/TX и состояние DNS. Старый handshake не удаляется из-за простоя; даты/фактические counters не заменены simulated connection state.

Developer-only UI layout test разрешён только в disposable GitHub Actions environment. Он создаёт fixture без ключей, проверяет bounds/menu actions/close-window policy и сохраняет собственный native Aqua fixture PNG: actual label cells + cached widgets, с проверкой наличия glyph pixels. Такой offscreen renderer не доказывает production theme/window-server capture. Этот режим не является VPN test, не подтверждает target OS, реальные клики пользователя, modal quit/long menu tracking или accessibility acceptance. Нормальный путь программы не создаёт фиктивный Connected.


Rename меняет только kSecAttrLabel существующего Keychain item; ID и data после rename проверены на native CI. Control/bidi/пустые/слишком длинные labels не принимаются. ACL update/foreign requester tests остаются отдельным gate. Диагностика содержит только фиксированный allowlist числовых counters/state/build/OS fields; имя профиля/endpoint/IP/DNS servers/interface/keys/paths не копируются. Перед локальным NSSavePanel показывается полный preview; нет автоматической отправки. Fixture с private metadata markers проверена native self-test.

Run 38416695930 / source `8a3130770834455aa42cf91054cf0a5aace30fd7`: настоящий NSApp.run подтвердил automatic delegate launch/visible window и закрытие окна с сохранением процесса/таймера. Controller retained through run loop; developer test будит nextEvent после stop. Предыдущий run 38415293044 завис именно на завершении test loop, исправлен. Live modal quit, long menu tracking, accessibility и High Sierra остаются NOT_RUN.
