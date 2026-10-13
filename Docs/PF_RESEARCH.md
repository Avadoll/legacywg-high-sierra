# PF: исследование возможности защиты

Read-only CI run 38406580921, source 1b290edf742ab4c213afdfe5cb56514290d2f2eb, Intel macOS 15.7.9: PF был отключён, state table пуст, root rules содержали wildcard filter anchor com.apple/*, quick pass rules не найдены. Повторное чтение подтвердило прежний hash root rules. Probe не включал PF, не загружал anchor, не удалял правила или states. Экспортированы только hashes/counts, без чужих endpoint addresses/anchor names.

Это предпосылки для эксперимента на конкретном CI host, не доказательство kill switch или High Sierra. Пустая state table не проверяет поведение существующих TCP/UDP flows. В production UI защита всего трафика пока отсутствует, full profiles отклоняются.

Apple прямо описывает PF как механизм для системных служб и администраторов, а не публичный API массового продукта; возможны конфликты с системными/сторонними правилами. Рекомендуемый поддерживаемый путь — Network Extension. Для нашего legacy target это архитектурный риск, а не разрешение молча изменить backend или заявить совместимость: [TN3165](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api). Доступность и способ поставки NE на 10.13 требуют отдельной проверки.

До интеграции guard обязательны durable owned recovery journal, проверка root anchor ordering/foreign quick rules, семантики PF enable references, уже открытых states, реальный physical packet capture IPv4/IPv6/DNS, crash/GUI loss/helper recovery и отказ при несовместимой политике. Нельзя загружать global ruleset, выключать чужой firewall или обещать fail-closed по одной строке pfctl.
