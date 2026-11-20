# AI Security Workflow

**Визуальная платформа автоматизации проверок безопасности**

Кейс Банка «Центр-инвест» · [CyberGarden 2026](https://cybergarden.ru)

Репозиторий: [github.com/VinfinityVois/INVEST](https://github.com/VinfinityVois/INVEST)

---

## О проекте

**AI Security Workflow** — это конструктор автоматических сценариев проверки безопасности кода в стиле n8n.

Пользователь **без написания кода** собирает workflow из блоков (нод):

1. Запускает проверку (кнопка или расписание)
2. Сканирует код **собственными анализаторами** (секреты, SCA, SAST)
3. Получает **AI-объяснения** рисков простым языком
4. Отправляет готовые рекомендации разработчикам (Telegram / Email / Webhook)

Платформа ориентирована на небольшие команды и стартапы, которым недоступны тяжёлые корпоративные AppSec-инструменты.

**Целевой стек для анализа:** Kotlin + Spring Boot + Gradle (Kotlin DSL).

---

## Проблема, которую решаем

- Небольшие команды выпускают продукт быстро, безопасность держится на внимательности разработчиков
- Типовые ошибки: тестовые ключи в коде, устаревшие зависимости, ошибки контроля доступа
- После релиза такие проблемы обходятся дорого
- Корпоративные сканеры сложны и часто недоступны стартапам

**Решение:** визуальный конструктор + собственные анализаторы + AI, который объясняет, а не пугает техническим жаргоном.

---

## Ключевые возможности

### Must-have

| Возможность | Описание |
|-------------|----------|
| **Visual Workflow Builder** | Drag-and-drop конструктор нод (React Flow) |
| **Собственные сканеры** | Secrets, SCA, SAST Kotlin — без Semgrep/Gitleaks/Trivy |
| **Классификация угроз** | Critical / High / Medium / Low |
| **AI-объяснения** | LLM агрегирует findings и даёт рекомендации |
| **Уведомления** | Telegram **или** SMTP **или** HTTP Webhook |
| **Real-time выполнение** | Статусы нод и данные между ними в реальном времени |
| **Триггеры** | Ручной запуск и по расписанию (cron) |
| **Логика** | If/Else, сравнение, regex-фильтры |

### Задачи со звёздочкой (бонусы)

| Бонус | Описание |
|-------|----------|
| **Библиотека шаблонов** | Публикация / просмотр / клонирование готовых workflow |
| **CI/CD интеграция** | Запуск как job в GitHub Actions / GitLab CI, fail при critical |
| **AI-генерация сценария** | «Каждый день в 14:00 проверяй секреты и шли на почту» → готовый workflow |

---

## Архитектура

```
┌─────────────────────────────────────────────────────────────┐
│  Frontend (React + TypeScript + React Flow)                 │
│  • Visual Workflow Editor                                   │
│  • Node palette + property panel                            │
│  • Real-time execution view                                 │
│  • Template library + AI workflow generator (бонусы)        │
└──────────────────────┬──────────────────────────────────────┘
                       │ REST / WebSocket
┌──────────────────────▼──────────────────────────────────────┐
│  Backend (FastAPI / Python) + Workflow Engine               │
│  • CRUD workflows                                           │
│  • Node Registry (плагинная система)                        │
│  • Execution state machine                                  │
│  • Encrypted secrets store                                  │
└──────┬──────────────────┬──────────────────┬────────────────┘
       │                  │                  │
       ▼                  ▼                  ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────────┐
│ Own Scanners │  │ AI Service   │  │ Notifications    │
│ • Secrets    │  │ (Ollama /    │  │ Telegram / SMTP  │
│ • SCA        │  │  free API)   │  │ / Webhook        │
│ • SAST Kotlin│  │ only explain │  │                  │
│ • Classifier │  │              │  │                  │
└──────────────┘  └──────────────┘  └──────────────────┘
```

### Принципы

1. **Node = плагин** — новая нода = новый класс + регистрация, без правок ядра
2. **Собственные анализаторы** — обнаружение только своими правилами (regex, парсеры, эвристики)
3. **LLM только объясняет** — не ищет уязвимости, не выдумывает CVE
4. **On-prem ready** — можно переключиться на локальную LLM одной настройкой

---

## Жёсткие ограничения кейса

**Запрещено:**
- Semgrep, Gitleaks, Trivy, detekt (с готовыми security-правилами)
- Любые готовые сканеры и их движки
- LLM вместо собственных анализаторов для **обнаружения**
- n8n / Node-RED как основа решения
- Сканирование чужих систем (только тестовый репозиторий организаторов)

**Разрешено:**
- regex, парсеры, tree-sitter / Kotlin PSI
- библиотеки сравнения версий, JSON-справочники уязвимостей
- собственные эвристические правила
- React Flow / Rete.js + свой executor (или Temporal / Conductor)

---

## Типы нод

### Триггеры
| Нода | Описание |
|------|----------|
| `manualTrigger` | Запуск по кнопке |
| `scheduleTrigger` | Cron / interval |

### Проверки безопасности (собственные)
| Нода | Описание |
|------|----------|
| `secretsScanner` | Поиск секретов (regex + entropy) |
| `scaScanner` | Анализ `build.gradle.kts` + справочник уязвимостей |
| `sastKotlin` | Статический анализ Kotlin / Spring Boot |
| `severityClassifier` | Critical / High / Medium / Low |

### Логика
| Нода | Описание |
|------|----------|
| `ifElse` | Ветвление по severity / количеству находок |
| `regexFilter` | Фильтрация findings |

### AI
| Нода | Описание |
|------|----------|
| `aiExplainer` | Объяснение рисков + рекомендации (JSON-схема, без галлюцинаций CVE) |

### Уведомления (один канал на выбор)
| Нода | Описание |
|------|----------|
| `notifyTelegram` | Telegram Bot |
| `notifySmtp` | Email |
| `notifyWebhook` | HTTP POST |

---

## Собственные сканеры (логика)

### Secrets
1. Обход текстовых файлов (исключая `build/`, `.git`, binary)
2. Набор regex (AWS keys, JWT, private keys, `password=`, `api_key=`, Bearer…)
3. Эвристика: высокая энтропия + ключевые слова в контексте
4. Маскирование значений в отчёте (`AKIA****…`)

### SCA
1. Парсинг `build.gradle.kts` (group:name:version)
2. Сравнение версий со справочником уязвимостей (JSON от организаторов)
3. Semver-сравнение диапазонов

### SAST (Kotlin / Spring Boot)
1. AST через tree-sitter или Kotlin PSI
2. Собственные правила:
   - Hardcoded credentials
   - `Runtime.exec` / ProcessBuilder с пользовательским вводом
   - Отсутствие `@PreAuthorize` на чувствительных эндпоинтах
   - SQL-конкатенация
   - Логирование чувствительных данных

---

## Технологический стек

| Слой | Технология |
|------|------------|
| Frontend | React 18+, TypeScript, Vite |
| Visual editor | **@xyflow/react** (React Flow) |
| Backend | FastAPI (Python 3.11+) — в разработке |
| Workflow engine | Собственный executor |
| БД | PostgreSQL |
| LLM | Ollama (локально) / GigaChat / free API |
| Парсинг Kotlin | tree-sitter-kotlin |
| Контейнеризация | Docker + Docker Compose |

---

## Структура репозитория

```
INVEST/
├── frontend/                    # Visual constructor
│   ├── src/
│   │   ├── components/
│   │   │   ├── WorkflowEditor.tsx   # React Flow canvas
│   │   │   └── NodePalette.tsx      # Drag-and-drop palette
│   │   ├── nodes/
│   │   │   ├── nodeRegistry.ts      # Все типы нод
│   │   │   └── WorkflowNode.tsx     # UI ноды + статусы
│   │   ├── types/
│   │   │   └── workflow.ts
│   │   ├── App.tsx
│   │   └── main.tsx
│   ├── package.json
│   └── vite.config.ts
├── backend/                     # (в разработке)
│   ├── app/
│   │   ├── nodes/               # BaseNode + scanners
│   │   ├── engine/              # Workflow executor
│   │   └── api/
│   └── requirements.txt
├── rules/                       # Собственные эвристики и справочники
├── demo-repo/                   # Учебный Kotlin/Spring Boot проект
├── Security_Scenario_Engine_Architecture.md
└── README.md
```

---

## Быстрый старт (Frontend)

### Требования
- Node.js 18+ (рекомендуется 20+)
- npm 9+

### Установка и запуск

```bash
# Клонировать репозиторий
git clone https://github.com/VinfinityVois/INVEST.git
cd INVEST/frontend

# Установить зависимости
npm install

# Запустить dev-сервер
npm run dev
```

Откройте в браузере: **http://localhost:5173**

### Что можно сделать в UI прямо сейчас

1. Перетаскивать ноды из левой палитры на холст
2. Соединять ноды (тянуть от правого handle к левому)
3. Нажать **▶ Запустить** — демо-прогон со статусами и mock-findings
4. Масштабировать холст, использовать MiniMap

### Сборка production

```bash
npm run build
npm run preview
```

---

## План разработки (48 часов)

| Этап | Задачи | Статус |
|------|--------|--------|
| 0–6 ч | Каркас: React Flow + FastAPI skeleton | Frontend canvas ✅ |
| 6–12 ч | Secrets Scanner + Notification + Manual Trigger | В работе |
| 12–18 ч | SCA Node (парсинг build.gradle.kts) | — |
| 18–26 ч | SAST Kotlin + Classifier | — |
| 26–32 ч | AI Node (LLM + JSON schema) | — |
| 32–38 ч | Real-time execution + If/Else + Schedule | Частично |
| 38–42 ч | Полировка UX, демо на тестовом репо | — |
| 42–46 ч | Бонусы: CI/CD API и/или библиотека шаблонов | — |
| 46–48 ч | Презентация + README | — |

---

## API (планируемое)

```
POST   /api/v1/workflows              # создать workflow
GET    /api/v1/workflows/{id}         # получить
POST   /api/v1/runs/trigger           # запустить (UI / CI)
GET    /api/v1/runs/{id}/status       # статус выполнения
POST   /api/v1/templates              # опубликовать шаблон
POST   /api/v1/templates/{id}/clone   # клонировать
POST   /api/v1/ai/generate-workflow   # генерация по тексту (бонус)
```

### Пример CI/CD (бонус)

```yaml
# .github/workflows/security.yml
security-check:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - name: Trigger security workflow
      run: |
        curl -X POST "$PLATFORM_URL/api/v1/runs/trigger" \
          -H "Authorization: Bearer ${{ secrets.TOKEN }}" \
          -H "Content-Type: application/json" \
          -d '{"workflow_id":"...","repo_url":"${{ github.repository }}","branch":"${{ github.ref_name }}"}'
```

---

## Документация

- [Архитектура (подробно)](./Security_Scenario_Engine_Architecture.md) — требования кейса, модель данных, алгоритмы сканеров, план на 48 часов

---

## Команда

Проект разрабатывается в рамках хакатона **CyberGarden 2026** для кейса Банка «Центр-инвест».

---

## Лицензия

Учебный / хакатонный проект. Использование кода — на усмотрение команды.
