# Model evaluation

Verified after regenerating the chronological synthetic dataset with seed 42 and retraining model `v20260724-141525` on 24 July 2026.

## Holdout summary

| Metric | Result |
|---|---:|
| Macro F1 | 0.9683 |
| Weighted F1 | 0.9922 |
| Classifier false-positive rate | 0.0012 |
| Alert false-positive rate at selected threshold | 0.0023 |
| Alert precision | 0.9714 |
| Alert recall | 0.8947 |
| Anomaly PR-AUC | 0.7417 |
| Selected risk threshold | 50.0 |

The threshold was selected on validation data by maximizing attack recall while requiring alert false-positive rate at or below 1%. At 50.0, validation precision was 0.9780, recall was 0.9175, and alert false-positive rate was 0.0025.

## Per-class holdout results

| Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| Brute force | 1.000 | 0.962 | 0.980 | 26 |
| Credential misuse | 1.000 | 1.000 | 1.000 | 6 |
| Device spoofing | 1.000 | 1.000 | 1.000 | 6 |
| Impossible travel | 0.938 | 0.750 | 0.833 | 20 |
| Lateral movement | 1.000 | 1.000 | 1.000 | 18 |
| Normal | 0.993 | 0.999 | 0.996 | 864 |

## Confusion matrix

Class order: brute force, credential misuse, device spoofing, impossible travel, lateral movement, normal.

```text
[[25, 0, 0,  0, 0,   1],
 [ 0, 6, 0,  0, 0,   0],
 [ 0, 0, 6,  0, 0,   0],
 [ 0, 0, 0, 15, 0,   5],
 [ 0, 0, 0,  0,18,   0],
 [ 0, 0, 0,  1, 0, 863]]
```

Device spoofing is cleanly separated in this generated holdout after adding correlated spoof sequences and benign browser/OS updates, replacements, resets, and shared devices. Impossible travel remains the weakest class at 0.75 recall; five of twenty holdout events were classified as normal. These synthetic results demonstrate the workflow and are not evidence of production efficacy.
