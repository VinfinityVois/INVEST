# Demo Vulnerable Spring Boot App

Учебный Kotlin + Spring Boot проект **с намеренными уязвимостями** для проверки AI Security Workflow.

## Что заложено

### Secrets
- AWS-like access key в `application.yml`
- Hardcoded API key / password в Kotlin-коде
- Bearer token и secret fallback

### SCA
- Устаревшие зависимости в `build.gradle.kts` (Log4j 2.14.1 и др.)

### SAST
- SQL injection через конкатенацию
- Публичный чувствительный маршрут (`permitAll`)
- CORS с `*` + credentials
- Отключённая проверка hostname TLS

## Как тестировать в AI Security Workflow

1. Git source:
   - URL: `https://github.com/VinfinityVois/INVEST`
   - ref: `test-repo`
2. Или ZIP папки `demo-app`
3. Ноды: Secrets → SCA → SAST → AI explain → Gate

Сканеры читают только файлы; Gradle из проекта не запускается.
