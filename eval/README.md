# INVEST evaluation

The benchmark runner compares INVEST's custom detector output with the training repository's published ground truth. It reads source files as data only and never executes Gradle, Maven, or repository scripts.

## Secrets benchmark

From the INVEST repository root, after cloning the public training repository beside it:

```powershell
python eval/run_secrets_benchmark.py --repo-root ..\training\training-project --ground-truth ..\training\ground-truth\training-findings.json --output eval\reports\training-secrets.json
```

The report includes precision, recall, F1, missed expected findings, false positives, and triggered SECRET controls. The runner exits with code 1 if expected findings are missed or a SECRET control is triggered.


## Gradle SCA benchmark

Run against the public static-analysis training project (do not run its Gradle wrapper):

```powershell
python eval/run_sca_benchmark.py --repo-root ..\training\training-project --ground-truth ..\training\ground-truth\training-findings.json --output eval\reports\training-sca.json
```

The SCA runner reads Gradle build files, optional `gradle.properties` and `gradle.lockfile`, then compares exact dependency coordinates and advisory ranges. It never invokes Gradle, Maven, or project scripts.
