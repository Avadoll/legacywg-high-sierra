# Hostname Endpoint: границы реализации

Добавлено 13 октября 2026. Native CI проверка ожидается.

ConfigCore принимает только валидированный ASCII hostname. Validate/импорт не выполняют DNS. При Start сначала проверяется весь split plan, затем системный resolver разрешает имена с общим пятисекундным deadline, и лишь после этого создаются UAPI/utun/routes/DNS. Повторные имена внутри профиля разрешаются один раз, порты peers остаются отдельными. Ошибки не включают hostname, IP или внутренний resolver error.

Закреплённый Go 1.24.13 использует native libc resolver на Darwin без необходимости cgo tool: `.tools/go1.24.13/go/src/net/conf.go`, `goosPrefersCgo`; worker environment очищен helper. Используется `net.Resolver.LookupNetIP`, без собственного DNS protocol/backend. Таймаут возвращает отказ до изменений сети; helper завершает worker после отказа. Нет накопления зависших lookup между worker sessions.

Не более 32 ответов. Адреса unspecified/multicast/link-local/scoped отклоняются; IPv4-mapped нормализуются. Все AllowedIPs всех peers проверяются до выбора адреса. Предпочитается первый допустимый IPv4, затем IPv6; это не reachability test. Один адрес фиксируется на сеанс. Нет автоматического fallback на другой ответ, смены IP без переподключения или protected reconnect.

Bootstrap обращается к текущему системному resolver до настройки tunnel DNS, поэтому hostname может быть виден существующему DNS provider. У этой split версии нет заявленного fail-closed режима. Для будущего protected mode нужна отдельная проверенная bootstrap/reconnect политика; этот код нельзя использовать для обещания отсутствия DNS утечек.

Тесты проверяют IPv6-only/mapped ответы, overlap другого peer, unsafe/oversized ответы, дедупликацию, deadline и отсутствие metadata в errors. Native encrypted localhost endpoint test проверяет связку system resolution → official engine → authenticated helper → encrypted traffic; localhost не доказывает запрос к внешнему DNS или внешнему серверу.
