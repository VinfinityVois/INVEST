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
add("source.git","Git repository","Source","Источник из allowlist Git.",[("event","event")],[("source","source")],{"type":"object","properties":{"url":{"type":"string"},"ref":{"type":"string"}}})
add("source.upload","Workspace source","Source","Каталог проекта внутри WORKSPACE_ROOT.",[("event","event")],[("source","source")],{"type":"object","properties":{"path":{"type":"string","description":"Относительный путь внутри WORKSPACE_ROOT"}}})
add("scan.secrets","Secrets scanner","Security","Собственный поиск секретов.",[("source","source")],[("findings","findings")])
add("scan.sca","Dependency scanner","Security","Проверка Gradle зависимостей по advisories.",[("source","source")],[("findings","findings")])
add("scan.sast","Kotlin SAST","Security","Статический анализ Kotlin/Spring.",[("source","source")],[("findings","findings")])
add("findings.merge","Merge findings","Logic","Объединение результатов.",[("findings","findings")],[("findings","findings")])
add("logic.if","Condition","Logic","Условное ветвление по числу и атрибутам находок.",[("findings","findings")],[("true","findings"),("false","findings")],{"type":"object","properties":{"field":{"type":"string","default":"finding_count","description":"finding_count, critical_count, high_count, medium_count, low_count, info_count или severity_counts.*"},"operator":{"type":"string","enum":["eq","ne","gt","gte","lt","lte","contains","not_contains","regex","exists"],"default":"gt"},"value":{"type":["string","number","boolean"],"default":0}},"required":["field","operator"]})
add("ai.explain","AI explanation","AI","Контекстное объяснение подтверждённых находок; AI не меняет результаты сканеров.",[("findings","findings")],[("report","report")],{"type":"object","properties":{"language":{"type":"string","enum":["ru","en"],"default":"ru"},"max_findings":{"type":"integer","minimum":1,"maximum":25,"default":20}}})
add("notify.webhook","Webhook","Notify","Отправка безопасной сводки на HTTPS endpoint из allowlist.",[("report","report")],[],{"type":"object","properties":{"url":{"type":"string","format":"uri","description":"HTTPS URL; hostname должен входить в WEBHOOK_ALLOWED_HOSTS"}},"required":["url"]})
add("ci.gate","CI security gate","CI","Блокирует workflow при находках выше заданного порога.",[("findings","findings")],[("result","gate")],{"type":"object","properties":{"block_on":{"type":"array","items":{"type":"string","enum":["CRITICAL","HIGH","MEDIUM","LOW","INFO"]},"default":["CRITICAL","HIGH"]},"warn_on":{"type":"array","items":{"type":"string","enum":["CRITICAL","HIGH","MEDIUM","LOW","INFO"]},"default":["MEDIUM","LOW","INFO"]}}})
