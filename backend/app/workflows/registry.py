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
add("source.upload","Upload archive","Source","Загруженный архив.",[("event","event")],[("source","source")])
add("scan.secrets","Secrets scanner","Security","Собственный поиск секретов.",[("source","source")],[("findings","findings")])
add("scan.sca","Dependency scanner","Security","Проверка Gradle зависимостей по advisories.",[("source","source")],[("findings","findings")])
add("scan.sast","Kotlin SAST","Security","Статический анализ Kotlin/Spring.",[("source","source")],[("findings","findings")])
add("findings.merge","Merge findings","Logic","Объединение результатов.",[("findings","findings")],[("findings","findings")])
add("logic.if","Condition","Logic","Условное ветвление.",[("findings","findings")],[("true","findings"),("false","findings")])
add("ai.explain","AI explanation","AI","Объяснение подтверждённых находок, не детекция.",[("findings","findings")],[("report","report")])
add("notify.webhook","Webhook","Notify","Уведомление на разрешённый endpoint.",[("report","report")])
add("ci.gate","CI security gate","CI","Пороговый security gate.",[("findings","findings")],[("result","gate")])
