# System Architecture

## Project Title

SQL-Backed ML Phishing Detection & URL Reputation System

---

## Overview

The system combines machine learning with a SQL-based reputation and scan-history layer.

The machine learning model performs phishing detection using deployment-safe features extracted directly from the URL string.

The SQL layer stores:

- URL reputation
- ML results
- verified reputation
- scan count
- scan history
- timestamps

---

## Pipeline A — Model Training

Dataset
↓
Data Cleaning
↓
EDA
↓
Deployment-Safe Feature Engineering
↓
Exact URL Deduplication
↓
Train / Validation / Test Split
↓
Model Training
↓
Validation Evaluation
↓
Threshold Optimization
↓
Hostname-Disjoint Generalization Test
↓
Final Model Selection
↓
Final Test Evaluation
↓
Saved Model Artifact

Final Model:

HistGradientBoosting

Decision Threshold:

0.14

Predictor Features:

22

---

## Pipeline B — Real-Time Inference

User URL
↓
URL Validation
↓
URL Normalization
↓
SQL Reputation Lookup
↓
Verified Reputation Available?

YES
↓
Return Verified Reputation

NO
↓
Extract 22 URL Features
↓
Load HistGradientBoosting Model
↓
Generate Phishing Probability
↓
Apply Threshold 0.14
↓
Generate Final ML Prediction
↓
Update SQL Reputation
↓
Store Scan History
↓
Return Result

---

## Target Mapping

0 = Legitimate

1 = Phishing

---

## Final Model Performance

Accuracy: 0.994250

Precision: 0.993170

Recall: 0.993368

F1 Score: 0.993269

F2 Score: 0.993328

ROC-AUC: 0.998217

PR-AUC: 0.998622

Final Test Samples: 35,306

Confusion Matrix:

TN = 20,125

FP = 103

FN = 100

TP = 14,978

---

## Deployment-Safe Features

1. url_length
2. domain_length
3. path_length
4. query_length
5. dot_count
6. hyphen_count
7. underscore_count
8. slash_count
9. question_count
10. equal_count
11. ampersand_count
12. at_count
13. percent_count
14. digit_count
15. letter_count
16. digit_ratio
17. letter_ratio
18. is_https
19. is_domain_ip
20. subdomain_count
21. suspicious_word_count
22. url_entropy

---

## Database Tables

### url_reputation

Stores the latest reputation information for every unique URL.

### scan_history

Stores every scan event.

---

## Security Design

The current implementation analyzes the URL string only.

The application does not automatically visit arbitrary submitted URLs.

This reduces exposure to malicious content and server-side request forgery risks.

---

## Important Limitation

The model is based primarily on lexical URL features.

It does not currently inspect:

- webpage content
- DNS reputation
- WHOIS data
- SSL certificate reputation
- external threat intelligence
- domain age
- browser behavior

Therefore, individual unseen URLs can still produce false positives or false negatives.

Verified SQL reputation provides an additional mechanism for trusted reputation overrides.