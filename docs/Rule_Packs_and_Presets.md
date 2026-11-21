# Rule packs и готовые presets

**Проект:** AI Security Workflow · Центр-инвест  
**Ограничение ТЗ:** без Semgrep/Gitleaks/Trivy/detekt; LLM не детектит.

## Зачем

| Слой | Роль |
|------|------|
| Rule packs | Подключаемые наборы правил secrets / SCA / SAST / policies |
| Presets | Готовые workflow: clone → repo/webhook → Run |
| Policies | bank-strict, startup-lenient для ci.gate |

## Структура

```text
rules/
  secrets/core.yml, spring-config.yml
  sast/injection.yml, spring-security.yml, idor-bac.yml
  sca/spring-boot-starters.json
  policies/bank-strict.yml, startup-lenient.yml
presets/
  manifest.json
  quick-secrets.json, pr-gate.json, nightly-full.json, spring-boot-audit.json
```

## Config нод

```json
// scan.secrets
{ "rule_packs": ["secrets-core", "secrets-spring"], "min_confidence": 0.4 }

// scan.sast
{ "rule_packs": ["sast-injection", "sast-spring-security", "sast-idor-bac"] }

// ci.gate
{ "policy_pack": "bank-strict" }
```

## API

- `GET /api/rule-packs`
- `GET /api/presets`
- `POST /api/presets/{id}/clone`

Presets (built-in) vs templates (БД, publish/clone) — два таба в UI.

## План внедрения

1. Вынести secrets в `rules/secrets/core.yml`
2. `rules_loader` + `rule_packs` в registry
3. 2–3 SAST YAML
4. presets/manifest + 3 graph JSON
5. UI Clone + multi-select packs
6. policies → ci.gate

## Текст для защиты

> Не один монолитный сканер, а библиотека собственных алгоритмов (rule packs) и готовых сценариев (presets). Новое правило = файл в rules/, без чужих движков.

Полная спецификация форматов YAML/JSON — в артефактах команды / расширенной версии docs при необходимости.
