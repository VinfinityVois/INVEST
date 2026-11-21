# Demo runbook — Центр-инвест / CyberGarden 2026

Цель: за 3–5 минут показать полный контур на публичном учебном Kotlin/Spring-проекте. Репозиторий сканируется как данные: Gradle, Maven и проектные скрипты не запускаются.

## До презентации

1. В корневом \`.env\` задать:
   \`\`\`env
   ALLOWED_TARGETS=https://github.com/TBagirov/training
   NOTIFY_WEBHOOK_ALLOWED_HOSTS=webhook.site
   LLM_BASE_URL=https://api.openai.com/v1
   LLM_MODEL=<your-openai-compatible-model>
   LLM_API_KEY=<your-api-key>
   \`\`\`
2. Создать уникальный endpoint на https://webhook.site/ и сохранить полный HTTPS URL.
3. Пересобрать сервисы после изменения \`.env\`:
   \`\`\`powershell
   docker compose up -d --build api worker frontend
   \`\`\`
4. Проверить http://localhost:8000/health и статус AI provider в интерфейсе. Ключ API не вводится в UI и не должен попадать в workflow.

## Показ

1. Открыть редактор и показать визуальный граф: Manual trigger → Git source → Secrets / SCA / SAST → Merge → AI → Webhook; Merge также подключён к Security Gate.
2. Убедиться, что Git source использует закреплённый commit \`fe1fcbe212669783480666b9b60147c8a8c6eef4\` и путь \`training-project\`.
3. Указать уникальный webhook URL в настройках Webhook и запустить workflow.
4. Показать live execution trace: каждый из трёх сканеров должен завершиться \`completed\`; AI — \`completed\`; Webhook — \`delivered\`.
5. Открыть Findings, объяснение AI, решение Security Gate и JSON на webhook.site. Gate \`BLOCK\` — валидный результат строгой политики, а не ошибка сканера; backend помечает такой run как \`failed\`, потому что gate остановил pipeline.

## Автоматический прогон из PowerShell

Сначала создай администратора по инструкции «Первый вход» в README. Для автоматического сценария передай учётные данные через переменные текущего PowerShell-процесса (не добавляй их в `.env`, репозиторий или аргументы команды):

```powershell
$env:INVEST_DEMO_EMAIL = "admin@example.test"
$secure = Read-Host "Пароль администратора" -AsSecureString
$env:INVEST_DEMO_PASSWORD = [Net.NetworkCredential]::new("", $secure).Password
.\scripts\demo.ps1 -WebhookUrl "https://webhook.site/<unique-id>"
Remove-Item Env:INVEST_DEMO_EMAIL, Env:INVEST_DEMO_PASSWORD
```

Скрипт входит через `/api/auth/login`, хранит HttpOnly session cookie только в памяти процесса, выполняет демонстрацию и отзывает сессию через logout. По умолчанию отправляет Origin `http://localhost:5173`; для другого frontend origin укажи `-FrontendOrigin` и добавь его в `ALLOWED_ORIGINS`.
\`\`\`powershell
.\\scripts\\demo.ps1 -WebhookUrl "https://webhook.site/<unique-id>"
\`\`\`

Скрипт создаёт workflow из \`examples/demo-workflow.json\`, ставит run в очередь, ждёт завершения и проверяет:
- Secrets, SCA и SAST завершились успешно;
- AI explanation завершился успешно;
- webhook действительно доставлен;
- Security Gate вернул \`PASS\`, \`WARN\` или \`BLOCK\`.

\`BLOCK\` принимается как ожидаемое решение политики, если сканеры, AI и webhook завершились успешно. Сетевой сбой webhook или отсутствие AI-конфигурации приводят к ошибке проверки.

## Если что-то не готово

- \`configuration_required\` у AI: проверить \`LLM_BASE_URL\`, \`LLM_MODEL\`, \`LLM_API_KEY\`, затем пересоздать api и worker.
- Webhook failed: проверить точное совпадение hostname с \`NOTIFY_WEBHOOK_ALLOWED_HOSTS\`, HTTPS/443 и доступность endpoint.
- Git source blocked: проверить точный URL в \`ALLOWED_TARGETS\`; не добавлять wildcard.
- Benchmark: команды и формат отчётов находятся в \`eval/README.md\`.

Не показывать \`.env\`, API keys, masked values или секреты из тестового проекта на слайдах и в записи экрана.


## Автоматический запуск из CI/CD

`.github/workflows/security-check.yml` поддерживает и ручной `workflow_dispatch`, и reusable workflow через `workflow_call`. Чтобы запускать проверку на каждый Pull Request в целевом репозитории, добавьте туда файл `.github/workflows/invest-security.yml`:

```yaml
name: INVEST security gate

on:
  pull_request:
    branches: [main]

jobs:
  security:
    uses: VinfinityVois/INVEST/.github/workflows/security-check.yml@feat/platform-foundation
    with:
      workflow_id: ${{ vars.INVEST_WORKFLOW_ID }}
    secrets:
      INVEST_API_BASE_URL: ${{ secrets.INVEST_API_BASE_URL }}
      INVEST_CI_TOKEN: ${{ secrets.INVEST_CI_TOKEN }}
```

В целевом репозитории задайте Actions variable `INVEST_WORKFLOW_ID` (UUID сохранённого workflow) и secrets `INVEST_API_BASE_URL` и `INVEST_CI_TOKEN`. Для production закрепите reusable workflow на проверенном release tag или commit SHA вместо изменяемой feature-ветки. Не используйте `pull_request_target`: проверка не должна получать секреты в контексте недоверенного кода PR.
