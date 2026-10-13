# Статус туннеля и peers

Добавлено 13 октября 2026; native multi-peer run 38405248722 / source 0705cbe1b625ff8f84f4f5b4c3959cc56d7a8dfe прошёл: два independent encrypted peers, отдельные counters и rollback.

`tunnel_started` означает наличие работающего engine и принадлежащего ему native interface. `Connected` в текущем IPC означает, что хотя бы один peer когда-либо завершил handshake в этом сеансе; GUI пишет «Handshake получен», не обещает доступность всех peers или защищённость всего трафика. `Connecting` означает ожидание первого handshake. Нет default health-check к третьей стороне.

`peer_details` содержит только номер peer в исходном порядке профиля, RX/TX и последний handshake timestamp. Внутреннее соответствие engine public key → profile index остаётся в памяти worker. В public IPC/экспорт не передаются ключи, endpoints или raw UAPI. Строки ключей копируются отдельно, чтобы mapping не удерживал весь key-bearing UAPI buffer.

Порядок UAPI engine не считается порядком профиля. Неизвестные/дублированные/пропущенные peers, malformed statistics, переполнение суммарных counters и превышение границ возвращают фиксированную ошибку. Timestamp из будущего не считается доказательством handshake.

Старый handshake сохраняется и показывается с датой; quiet peer не отключается автоматически. Last handshake не является uptime/health-check и не доказывает, что endpoint сейчас отвечает. После Disconnect и новой сессии статистика начинается заново. Полноценный timeout/cancel/network reconnect остаётся открытой работой.

Unit tests проверяют reordered peers, отказ malformed/foreign counters, privacy DTO и сохранение тихого handshake. Новый integration test создаёт два независимых официальных netstack peers с разными ключами/портами, проверяет шифрованные ответы через native utun и отдельные counters/handshakes, затем исходное состояние routes. У него только ephemeral test keys и benchmark addresses; он не подключается к пользовательскому серверу.
