# План работ: что доделать и что начать с нуля

**Ветка:** `feat/platform-foundation`  
**Репозиторий:** [VinfinityVois/INVEST](https://github.com/VinfinityVois/INVEST)  
**ТЗ:** PDF «AI Security Workflow» · Центр-инвест · CyberGarden 2026  
**Дата:** 2026-11-20  

Уже работает (не трогать без нужды): React Flow, manual trigger, source git/upload, secrets/SCA/SAST базово, merge, logic.if, ai.explain, webhook-нода, ci.gate, SSE, vault, docker-compose, тесты.

Ниже — только **дыры** и **недоделки**, в порядке «что делать сейчас».

---

## A. Начать с нуля (функции нет в коде)

| ID | Что сделать | Зачем по ТЗ | Оценка | Как начать (первые шаги) |
|----|-------------|-------------|--------|---------------------------|
| **N1** | Merge / default branch | Жюри видит `main` | 15 мин | PR `feat/platform-foundation` → `main` или Settings → default branch |
| **N2** | `trigger.schedule` | Задача 2: «по кнопке, **расписанию**» | 1–3 ч | 1) `add("trigger.schedule", …)` в registry 2) config: cron 3) worker/APScheduler или polling job → `POST run` 4) нода на палитре |
| **N3** | `logic.compare` и/или `logic.regex` | Задача 2: сравнение, regex | 1–2 ч | Нода: вход findings/any → true/false или filter; config field/op/value или pattern |
| **N4** | Стабильный e2e notify | Задача 2 + техтр. 1 | 1–2 ч | Довести `notify.webhook`: POST JSON (stats + top findings + AI summary) на webhook.site; проверить в UI |
| **N5** | Demo-скрипт / demo-workflow | Презентация | 30–60 мин | Сохранённый graph JSON + README «5 шагов до findings» |
| **N6** | CI job для *продукта* (*-2) | Бонус CI/CD | 1 ч | `.github/workflows/security-check.yml`: curl trigger API → ждать run → exit 1 если gate=fail |
| **N7** | Библиотека шаблонов (*-1) | Бонус | 3–6 ч | Таблица templates, publish/list/clone API, кнопка в UI |
| **N8** | AI-генерация графа (*-3) | Бонус | 4–8 ч | `POST /ai/generate-workflow` → JSON schema → validate_graph → nodes на холст |

**Стартовать сегодня (обязательный минимум «нет»):** N1 → N4 → N2 (или явный skip в презентации) → N5.

---

## B. Доделать (есть, но не закрывает ТЗ)

| ID | Что доделать | Сейчас | Цель | Как доделать |
|----|--------------|--------|------|--------------|
| **D1** | E2E на учебном Kotlin-репо | Run работает, сценарий не зафиксирован | Один репо → 3 сканера → AI → notify без сюрпризов | Залить sample / allowlist URL; прогнать; записать команды в README |
| **D2** | Secrets | Regex + assignment | Меньше шума, ближе к эталону | Entropy ≥ порога; placeholders; при необходимости git history |
| **D3** | SCA | Gradle + JSON advisories | Эталонные CVE/версии | `libs.versions.toml`; Spring Boot managed map; semver ranges |
| **D4** | SAST | Эвристики SQLi/TLS/CORS/IDOR | 2–3+ класса эталона стабильно | Правила под эталон; ideally tree-sitter; не раздувать scope |
| **D5** | Порты в UI | Backend валидирует | Нельзя соединить findings→source | Проверка data_type при `onConnect`; красная подсветка |
| **D6** | Формы конфига | Ручные поля | Schema-driven | Рендер из `config_schema` манифеста |
| **D7** | AI на демо | Код есть, нужен `.env` | Видны объяснения, не «configuration_required» | Прописать LLM_*; показать readiness + completed в UI |
| **D8** | README поставки | Есть общий | «С нуля до findings за 5 мин» | compose, .env, demo graph, ожидаемые findings |

---

## C. Порядок работ на ближайшие сессии

### Сессия 1 — поставка и демо-каркас (P0)

1. **N1** — merge в `main`  
2. **D1** — один стабильный учебный проект + полный run  
3. **N4** — webhook реально уходит (webhook.site)  
4. **D7** — LLM в `.env`, AI-нода даёт текст  
5. **N5** + **D8** — README и demo path  

*Результат: можно показывать жюри end-to-end.*

### Сессия 2 — закрыть дыры задачи 2–3 (P0/P1)

6. **N2** — `trigger.schedule` (cron)  
7. **N3** — хотя бы `logic.regex` или `logic.compare`  
8. **D2 / D3 / D4** — подгонка сканеров под эталон организаторов (после выдачи репо)  

### Сессия 3 — UX и бонусы

9. **D5** — typed ports в UI  
10. **N6** — CI job (* быстрый бонус)  
11. **N7 / N8** — только если P0 закрыт  

---

## D. Чеклист «можно сдавать must-have»

- [ ] Код в `main` (или default = foundation)  
- [ ] `docker compose up --build` поднимает стек  
- [ ] Drag-and-drop: trigger → source → secrets/sca/sast → merge → ai → notify/gate  
- [ ] Свои сканеры, без Semgrep/Gitleaks/Trivy  
- [ ] Severity у findings  
- [ ] AI объясняет, не детектит  
- [ ] Уведомление уходит (webhook достаточно)  
- [ ] Статусы нод live (SSE)  
- [ ] Schedule **есть** или осознанно объяснён gap  
- [ ] Скан только allowlist / учебный проект  

---

## E. Не делать

| Запрет ТЗ | Почему |
|-----------|--------|
| Semgrep, Gitleaks, Trivy, detekt (готовые rules) | Прямой запрет |
| LLM вместо собственных анализаторов | Прямой запрет |
| n8n / Node-RED как основа | Прямой запрет |
| Скан чужих prod-систем | Прямой запрет |

---

## F. Быстрые победы

| Время | Действие |
|-------|----------|
| 15 мин | **N1** Merge → main |
| 30 мин | Webhook.site + один run → скрин notify |
| 1 ч | **N2** schedule «каждые 5 мин» для демо |
| 1 ч | **N6** Actions: trigger + fail on gate |
| 2–3 ч | Правила SCA/SAST строго под эталонный репо |

---

## G. Связанные документы

- [Backlog_Dorabotka.md](./Backlog_Dorabotka.md) — полный бэклог с ID  
- [Platform_Foundation_Status.md](./Platform_Foundation_Status.md) — что уже реализовано  
- [Security_Scenario_Engine_Architecture.md](./Security_Scenario_Engine_Architecture.md) — архитектура  

**С чего начать прямо сейчас:** `N1` (merge) → `D1` (e2e на одном репо) → `N4` (notify) → `N2` (schedule).
