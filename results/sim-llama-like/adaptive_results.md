# Adaptive attacks - `sim:llama-like`

Best-of-12 per scenario, 3 seed(s). ASR = share of scenarios where any candidate succeeded.

| config | ALL | encoded_leak | low_sim_poison | redirect_exfil | soft_injection |
|---|---|---|---|---|---|
| none | 80.6% | 100.0% | 91.7% | 30.6% | 100.0% |
| ingestion | 60.4% | 88.9% | 83.3% | 0.0% | 69.4% |
| retrieval | 77.1% | 94.4% | 83.3% | 30.6% | 100.0% |
| prompt | 63.2% | 66.7% | 91.7% | 11.1% | 83.3% |
| output | 80.6% | 100.0% | 91.7% | 30.6% | 100.0% |
| all | 25.7% | 19.4% | 83.3% | 0.0% | 0.0% |

![adaptive](adaptive_asr.png)
