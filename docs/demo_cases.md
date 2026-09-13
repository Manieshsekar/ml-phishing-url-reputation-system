# Demonstration Cases

## Case 1 — Legitimate ML Result

URL:

https://www.google.com

Expected Source:

ml_model

Expected Result:

Legitimate

Observed approximate phishing probability:

0.0021

Observed approximate risk score:

0.21%

---

## Case 2 — Phishing-Like Synthetic URL

URL:

http://secure-login-verify.example/account/update

Expected Source:

ml_model

Expected Result:

Phishing

Observed approximate phishing probability:

0.999945

Observed approximate risk score:

99.99%

---

## Case 3 — Verified Reputation

URL:

https://trusted-demo.example

Expected Source:

verified_reputation

Expected Result:

Legitimate

Verified:

True

This demonstrates that trusted SQL reputation can be used instead of relying only on ML predictions.

---

## Case 4 — Known Model Limitation

URL:

https://github.com

Observed behavior during development:

The URL-only ML model produced a phishing prediction.

This demonstrates that high benchmark performance does not guarantee perfect predictions for every unseen domain.

The system therefore supports a verified SQL reputation layer and can later be extended with external threat intelligence.