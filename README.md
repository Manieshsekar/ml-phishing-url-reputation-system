# ML Phishing URL Reputation System

A SQL-backed machine learning system for detecting phishing URLs using deployment-safe URL features, a trained HistGradientBoosting classifier, SQLite reputation storage, and a Streamlit web interface.

Website Link: https://ml-phishing-url-reputation-system-hjfseyswgzhb3d4gnt399j.streamlit.app/

---

## Project Overview

This project detects whether a URL is likely to be:

- Legitimate
- Phishing

The system combines:

- Machine Learning
- URL Feature Engineering
- SQL Reputation Storage
- Scan History
- Verified Reputation Overrides
- Streamlit Dashboard

The system analyzes the URL string and does not automatically visit arbitrary websites.

---

## System Architecture

The project contains two main pipelines.

### Pipeline A — Model Training

Dataset  
→ Data Cleaning  
→ Exploratory Data Analysis  
→ Feature Engineering  
→ Leakage-Safe Split  
→ Model Training  
→ Validation  
→ Threshold Optimization  
→ Generalization Testing  
→ Final Model Selection  
→ Final Test Evaluation

### Pipeline B — Real-Time Detection

User URL  
→ Validation / Normalization  
→ SQL Reputation Lookup  
→ Verified Reputation Check  
→ ML Inference if Required  
→ Risk Score  
→ SQL Reputation Update  
→ Scan History  
→ Streamlit Result

---

## Final Model

Model:

HistGradientBoosting

Decision Threshold:

0.14

Number of Predictor Features:

22

Target Mapping:

- 0 = Legitimate
- 1 = Phishing

---

## Final Test Performance

| Metric | Score |
|---|---:|
| Accuracy | 0.994250 |
| Precision | 0.993170 |
| Recall | 0.993368 |
| F1 | 0.993269 |
| F2 | 0.993328 |
| ROC-AUC | 0.998217 |
| PR-AUC | 0.998622 |

Final test samples:

35,306

Confusion matrix:

```text
[[20125   103]
 [  100 14978]]



