# Rule packs и готовые presets

**Проект:** AI Security Workflow · Центр-инвест  
**Ограничение кейса:** обнаружение выполняют собственные правила платформы; LLM используется только для объяснения подтверждённых находок.

## Архитектура

| Слой | Назначение | Реализация |
|---|---|---|
| Rule packs | Подключаемые наборы правил Secrets / SCA / SAST / policy | YAML в `rules/`, загрузчик `backend/app/rules_loader.py` |
| Presets | Встроенные готовые workflow | JSON-каталог `presets/manifest.json` и `presets/*.json` |
| Templates | Публикуемые и копируемые пользовательские workflow | БД и API `/api/templates` |
| Policies | Пороговые решения Security Gate | YAML в `rules/policies/` |

Rule packs поддерживают наследование через `extends`; загрузчик проверяет идентификаторы, тип анализатора, структуру и ограничения содержимого. Циклы наследования и несовместимые типы анализаторов отклоняются. Содержимое правил не исполняется как код.

## Текущий каталог

- **Secrets:** базовые паттерны, Spring-конфигурация и дополнительные контекстные эвристики.
- **SCA:** Maven/Gradle; локальный advisory snapshot и каталог Spring Boot starters.
- **SAST:** Kotlin/Spring правила для injection, Spring Security и IDOR/BAC.
- **Policies:** `bank-strict`, `startup-lenient` и `secrets-zero`.
- **Built-in preset:** `pr-gate` — Manual trigger → Git source → Secrets/SCA/SAST → Merge → CI Gate.
- **Published templates:** отдельная библиотека с публикацией, поиском и клонированием очищенного графа.

Список доступен через `GET /api/rule-packs` и `GET /api/presets`; клонирование встроенного preset — `POST /api/presets/{id}/clone`. Публикация и клонирование пользовательских templates используют `/api/templates`.

## Конфигурация нод

```json
{
  "scan.secrets": {
    "rule_packs": ["secrets-core"],
    "min_confidence": 0.4
  },
  "scan.sca": {
    "rule_packs": ["sca-spring-boot"],
    "advisory_db": "maven-advisories",
    "starter_pack": "spring-boot-starters"
  },
  "scan.sast": {
    "rule_packs": ["sast-core"],
    "min_confidence": 0.4
  },
  "ci.gate": {
    "policy_pack": "bank-strict"
  }
}
```

## Ограничения, которые важно раскрыть на защите

- Maven advisory snapshot — ограниченный курируемый набор (41 advisory на дату, указанную в `data/README.md`), а не полный и автоматически обновляемый feed.
- Spring Boot managed-version snapshot покрывает выбранные версии и координаты, а не весь BOM.
- SAST остаётся ограниченным статическим анализом; межфайловый taint propagation — эвристический и не заменяет полноценный Kotlin PSI/AST, type resolution или call graph.
- Gradle/Maven и проектные скрипты не запускаются. Неизвестные версии и неразрешённые зависимости не угадываются.
- Встроенный каталог сейчас содержит один preset (`pr-gate`); остальные сценарии можно собрать вручную или опубликовать как templates.
- Публикация templates требует отдельного `TEMPLATE_PUBLISH_TOKEN`; секреты и локальные пути очищаются, webhook URL заменяется безопасным placeholder.

## Проверки

Backend tests проверяют загрузку и наследование packs, валидность preset-графа, очистку и клонирование templates. CI дополнительно запускает Secrets, SCA и SAST benchmark на публичном учебном репозитории. Результаты benchmark относятся к конкретному открытому набору и не гарантируют такую же полноту на скрытой вариации.
