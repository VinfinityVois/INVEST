# INVEST evaluation

The benchmark runner compares INVEST's custom detector output with the training repository's published ground truth. It reads source files as data only and never executes Gradle, Maven, or repository scripts. Matching accepts both each finding's primary location and its `alternateLocations`; each scanner detection can satisfy at most one expected finding (maximum one-to-one matching). The same location handling is applied to negative controls. SCA matches also retain exact group/artifact coordinate checks at alternate locations.

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


## Kotlin/Spring SAST benchmark

```powershell
python eval/run_sast_benchmark.py --repo-root ..\training\training-project --ground-truth ..\training\ground-truth\training-findings.json --output eval\reports\training-sast.json
```

The SAST runner compares Kotlin/Spring findings with exact file/line ground truth and reports precision, recall, F1, missed findings, false positives and triggered SAST controls. It reads source files only; project code is never executed.

## Full local benchmark sequence

Run all three commands above against the same pinned training checkout and ground-truth file. Keep the generated JSON reports as evidence; do not tune rules against a hidden organizer dataset unless that dataset is explicitly provided for evaluation.
