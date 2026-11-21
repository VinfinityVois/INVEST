# Что доделать и дотянуть

**Проект:** AI Security Workflow · Центр-инвест · CyberGarden 2026  
**Код:** `main` / `feat/platform-foundation` (состояние на 2026-11-21)  
**Фокус документа:** только пробелы и недотяжки. Работающий foundation сюда не входит.

---

## Краткая оценка

| Слой | Готовность | Комментарий |
|------|------------|-------------|
| Must-have (задачи 1–5) | ~90% | Можно демо; остались точечные дыры |
| Мин. техтребования | ~90–95% | Свои сканеры, LLM explain, UI, allowlist |
| Бонусы (*) | ~70–85% | Templates, CI job, AI-gen — есть; довести UX/стабильность |
| Сканеры «в глубину» | ~60–75% | База есть; эталон организаторов важнее идеального AST |

**Уже закрыто:** visual editor, manual + schedule, git/upload, secrets (+ entropy), SCA, SAST, merge, logic.if + compare, ai.explain, webhook, ci.gate, SSE, vault, templates API, AI workflow draft, CI security-check.yml, docker-compose, benchmarks, код в main.

---

## P0 — критично до демо

| ID | Что | Как дотянуть |
|----|-----|-------------|
| P0-1 | E2E на учебном репо | ZIP/Git → 3 сканера → AI → webhook; 5 шагов в README |
| P0-2 | Webhook notify | Payload на webhook.site; allowlist host |
| P0-3 | AI без configuration_required | LLM_* в .env; recreate api/worker |
| P0-4 | Сканеры vs эталон | eval/run_*_benchmark.py + ground-truth |
| P0-5 | Скрипт презентации | open → Run → findings → AI → webhook |

## P1 — дотянуть must-have

| ID | Что | Цель |
|----|-----|------|
| P1-1 | logic.regex | Нода или compare/contains на демо |
| P1-2 | Notify | webhook достаточно (ТЗ: один канал) |
| P1-3–5 | SCA/SAST/Secrets | Под эталон организаторов |
| P1-6–8 | Ports / forms / UI | Typed ports, schema forms, серый+зелёный |

## Бонусы *

| ID | Дотянуть |
|----|----------|
| *-1 Шаблоны | UI каталог + clone |
| *-2 CI | Docs secrets + demo workflow_id |
| *-3 AI-граф | 2–3 промпта для демо |

## Не делать

Semgrep/Gitleaks/Trivy/detekt · LLM-детекция · n8n/Node-RED · скан чужих prod.

**Приоритет:** P0 → P1 сканеры/UX → полировка *.

См. также: Plan_Dorabotka_i_Start.md, Rule_Packs_and_Presets.md.
