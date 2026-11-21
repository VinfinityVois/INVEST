from .schemas import NodeManifest, Port

class NodeRegistry:
    def __init__(self):
        self._nodes: dict[str, NodeManifest] = {}
    def register(self, manifest: NodeManifest):
        if manifest.type in self._nodes:
            raise ValueError(f"Duplicate node type: {manifest.type}")
        self._nodes[manifest.type] = manifest
    def get(self, node_type: str):
        return self._nodes.get(node_type)
    def all(self):
        return list(self._nodes.values())

registry = NodeRegistry()
def add(t, title, category, description, ins=(), outs=(), config=None):
    registry.register(NodeManifest(type=t,title=title,category=category,description=description,
      inputs=[Port(name=n,data_type=d) for n,d in ins],
      outputs=[Port(name=n,data_type=d) for n,d in outs],config_schema=config or {}))

add("trigger.manual","Manual trigger","Trigger","Запуск вручную.",outs=[("event","event")])
add("trigger.schedule","Schedule trigger","Trigger","Запуск сохранённого workflow по cron-расписанию.",outs=[("event","event")],config={"type":"object","required":["cron"],"properties":{"cron":{"type":"string","title":"Cron expression","default":"*/5 * * * *","description":"Пять полей cron; время интерпретируется в выбранном часовом поясе."},"timezone":{"type":"string","title":"Timezone","default":"UTC","description":"IANA timezone, например Europe/Amsterdam."}}})
add("source.git","Git repository","Source","Источник из allowlist Git.",[("event","event")],[("source","source")],{"type":"object","required":["url"],"properties":{"url":{"type":"string","title":"HTTPS Git URL","format":"uri","description":"Публичный HTTPS URL репозитория из ALLOWED_TARGETS."},"ref":{"type":"string","title":"Ветка или commit","default":"main","description":"Ветка, tag или полный commit SHA."},"subdirectory":{"type":"string","title":"Подкаталог","description":"Необязательная папка внутри checkout, например training-project."}}})
add("source.upload","Workspace source","Source","Каталог проекта внутри WORKSPACE_ROOT.",[("event","event")],[("source","source")],{"type":"object","required":["path"],"properties":{"path":{"type":"string","title":"Путь к проекту","description":"Относительный путь к загруженному проекту внутри WORKSPACE_ROOT."}}})
add("scan.secrets","Secrets scanner","Security","Собственный поиск секретов.",[("source","source")],[("findings","findings")],{"type":"object","properties":{"rule_packs":{"type":"array","title":"Наборы правил","items":{"type":"string"},"default":["secrets-core"],"description":"Выбери встроенные secrets packs; дочерний pack автоматически включает наследуемые правила."},"include_tests":{"type":"boolean","title":"Сканировать тесты","default":True,"description":"Отключи, чтобы исключить тестовые каталоги и fixture из анализа."},"min_confidence":{"type":"number","title":"Минимальная уверенность","minimum":0,"maximum":1,"default":0.4,"description":"Отбрасывать результаты с confidence ниже порога (0–1)."}}})
add("scan.sca","Dependency scanner","Security","Проверка Maven и Gradle зависимостей по локальным advisory snapshots и встроенным SCA packs.",[("source","source")],[("findings","findings")],{"type":"object","properties":{"rule_packs":{"type":"array","title":"SCA rule packs","items":{"type":"string","enum":["sca-maven-core","sca-spring-boot"]},"default":["sca-spring-boot"],"description":"Встроенные наборы SCA. Spring Boot pack наследует Maven/Gradle core и добавляет каталог starter-зависимостей."},"advisory_db":{"type":"string","title":"Advisory database","enum":["maven-advisories"],"default":"maven-advisories","description":"Версионированный локальный snapshot Maven advisories; произвольные пути и URL не принимаются."},"starter_pack":{"type":"string","title":"Starter catalog","enum":["none","spring-boot-starters"],"default":"spring-boot-starters","description":"Каталог Spring Boot starters используется только для классификации найденных зависимостей."},"include_dev":{"type":"boolean","title":"Include development dependencies","default":True,"description":"Включать test/provided и тестовые Gradle-конфигурации."},"use_lockfile":{"type":"boolean","title":"Use lockfiles","default":True,"description":"Использовать Gradle lockfiles для разрешённых версий и транзитивных зависимостей."},"min_confidence":{"type":"number","title":"Минимальная уверенность","minimum":0,"maximum":1,"default":0.4,"description":"Отбрасывать результаты с confidence ниже порога (0–1)."}}})
add("scan.sast","Kotlin SAST","Security","Статический анализ Kotlin/Spring.",[("source","source")],[("findings","findings")],{"type":"object","properties":{"rule_packs":{"type":"array","title":"Наборы правил","items":{"type":"string"},"default":["sast-core"],"description":"Выбери собственные SAST packs: injection, Spring Security, IDOR/BAC."},"include_tests":{"type":"boolean","title":"Сканировать тесты","default":True,"description":"Отключи, чтобы исключить Kotlin-файлы из тестовых каталогов."},"min_confidence":{"type":"number","title":"Минимальная уверенность","minimum":0,"maximum":1,"default":0.4,"description":"Отбрасывать результаты с confidence ниже порога (0–1)."}}})
add("findings.merge","Merge findings","Logic","Объединение результатов.",[("findings","findings")],[("findings","findings")])
add(
    "logic.if",
    "Condition",
    "Logic",
    "Условное ветвление.",
    [("findings", "findings")],
    [("true", "findings"), ("false", "findings")],
    {
        "type": "object",
        "required": ["field", "operator"],
        "properties": {
            "field": {
                "type": "string",
                "minLength": 1,
                "maxLength": 160,
                "default": "finding_count",
                "description": (
                    "Поле контекста: finding_count, critical_count, "
                    "high_count, medium_count, low_count, info_count, "
                    "severity_counts или вложенное поле findings."
                ),
            },
            "operator": {
                "type": "string",
                "enum": [
                    "exists",
                    "eq",
                    "ne",
                    "contains",
                    "not_contains",
                    "regex",
                    "gt",
                    "gte",
                    "lt",
                    "lte",
                ],
                "default": "gt",
            },
            "value": {
                "description": (
                    "Значение для сравнения. Для exists не требуется. "
                    "Для regex требуется строка."
                ),
            },
        },
    },
)
add("logic.compare","Compare findings","Logic","Фильтрует находки по полю и оператору; true/false порты передают соответствующие наборы.",[("findings","findings")],[("true","findings"),("false","findings")],{"type":"object","required":["field","operator","value"],"properties":{"field":{"type":"string","enum":["severity","rule_id","path","category","message","cve","cwe","count"],"default":"severity"},"operator":{"type":"string","enum":["equals","not_equals","contains","not_contains","greater_than","greater_or_equal","less_than","less_or_equal"],"default":"equals"},"value":{"type":"string","maxLength":256}}})
add("ai.explain","AI explanation","AI","Контекстное объяснение подтверждённых находок; AI не меняет результаты сканеров.",[("findings","findings")],[("report","report")],{"type":"object","properties":{"language":{"type":"string","enum":["ru","en"],"default":"ru"},"max_findings":{"type":"integer","minimum":1,"maximum":25,"default":20}}})
add("notify.webhook","Webhook","Notify","Отправляет сводку находок и AI-объяснения на allowlisted HTTPS webhook.",[("report","report")],[],{"type":"object","required":["url"],"properties":{"url":{"type":"string","format":"uri","title":"HTTPS webhook URL","description":"URL из webhook.site; домен должен быть разрешён в NOTIFY_WEBHOOK_ALLOWED_HOSTS."}}})
add("notify.telegram","Telegram","Notify","Отправляет plain-text summary в allowlisted Telegram chat_id. Token только из TELEGRAM_BOT_TOKEN.",[("report","report"),("findings","findings")],[],{"type":"object","required":["chat_ids"],"properties":{"chat_ids":{"type":"array","title":"Chat IDs","items":{"type":"string"},"minItems":1,"description":"Список numeric chat_id из TELEGRAM_ALLOWED_CHAT_IDS."},"message_template":{"type":"string","title":"Message template","maxLength":500,"description":"Плейсхолдеры: {status} {workflow} {total} {critical} {high} {medium} {low} {info} {run_id}"}}})
add("notify.email","Email","Notify","Отправляет plain-text summary через allowlisted SMTP. Секреты SMTP только из .env.",[("report","report"),("findings","findings")],[],{"type":"object","required":["to"],"properties":{"to":{"type":"array","title":"Recipients","items":{"type":"string","format":"email"},"minItems":1,"description":"Список получателей."},"subject_template":{"type":"string","title":"Subject template","maxLength":200},"body_template":{"type":"string","title":"Body template","maxLength":500,"description":"Плейсхолдеры: {status} {workflow} {total} {critical} {high} {medium} {low} {info} {run_id}"}}})
add("ci.gate","CI security gate","CI","Блокирует workflow при находках выше заданного порога.",[("findings","findings")],[("result","gate")],{"type":"object","properties":{"policy_pack":{"type":"string","title":"Профиль политики","default":"bank-strict","description":"Именованный профиль из rules/policies. Профиль полностью задаёт пороги CI gate."}}})
