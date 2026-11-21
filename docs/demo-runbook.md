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

Из корня репозитория:
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
