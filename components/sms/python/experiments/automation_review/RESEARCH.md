# SMS review: primary sources and engineering decisions

Reviewed 12 November 2026. This is a scoped review of challenge requirements, Indian fraud patterns, dataset provenance, calibration and Android measurement. It is not a claim to have exhaustively surveyed every paper or dataset. No new third-party raw corpus was downloaded or silently added to training.

| Primary source | Finding relevant to this project | Decision |
| --- | --- | --- |
| [Official Arm challenge, PS3](https://arm-education.github.io/Arm-Developer-Labs/Bharat_AI_SoC_2026_27.html) | The security assistant needs local threat evidence and practical advice. Llama-family advisory on ExecuTorch is required. | Keep detection and notification independent of later shared Llama advice. The current SMS app alone does not complete the full challenge requirements. |
| [RBI cyber threats and frauds, 2022](https://www.rbi.org.in/Scripts/BS_PressReleaseDisplay.aspx?prid=53185) | Secret requests, KYC threats, remote access and UPI receipt deception are relevant fraud cues. | Include both these scams and genuine OTP/payment messages in evaluation. A payment word alone is insufficient proof of fraud. |
| [RBI fraudulent use of its name, 2024](https://www.rbi.org.in/scripts/bs_pressreleasedisplay.aspx/BS_PressReleaseDisplay.aspx?prid=58595) | Impersonation includes advance fees, intimidation and bogus government/RBI claims. | Test impersonation and no-link payment demands, rather than requiring a URL for every scam. |
| [DoT electricity KYC scam, 2024](https://www.pib.gov.in/Pressreleaseshare.aspx?PRID=2025970&lang=2&reg=48) | Reported scams combine utility/KYC stories and malicious APKs. | Include utility and APK scenarios with genuine bill reminders as controls. |
| [CERT-In SOVA advisory, 2022](https://www.cert-in.org.in/s2cMainServlet?CACODE=CICA-2022-3093&pageid=PUBADV01) | Smishing can be the entry to Android banking malware. | Test install/remote-support lures. The SMS classifier does not scan installed APKs or prove malware identity. |
| [UCI SMS Spam Collection](https://archive.ics.uci.edu/dataset/228/sms+spam+collection) | An older spam research corpus with UK/Singapore sources and ham/spam labels. | Useful regression baseline; insufficient evidence for present Indian fraud protection. |
| [Mendeley three-class SMS dataset](https://data.mendeley.com/datasets/f45bkkt8pr/1) | 5,971 labelled messages; collection includes image-to-text conversion from Internet material. | Respect source/label limitations and campaign overlaps. Dataset size alone does not establish Indian deployment coverage. |
| [SmishTank dataset paper](https://arxiv.org/abs/2402.18430) | 1,090 community-submitted smishing samples. | Candidate future positive source after provenance/licence checks; needs independent ordinary-message controls and leakage review. It was not used in this run. |
| [Guo et al., calibration, ICML 2017](https://proceedings.mlr.press/v70/guo17a.html) | Model softmax outputs need not express real correctness probability. | Call current scores uncalibrated. Validate routing/calibration on development data before locking a fresh test set. |
| [Android Microbenchmark guidance](https://developer.android.com/topic/performance/benchmarking/microbenchmark-write) | Accurate performance work needs controlled benchmark configuration. | Treat the in-app debug batch as functional diagnostics. It is not a controlled release latency or battery benchmark. |

The RBI BE(A)WARE PDF was also located, but automated access was blocked. No claim in this review relies on reading that blocked PDF.

Research implies the largest remaining quality gap is labelled Indian ham/spam/scam coverage, especially Hindi/Hinglish and hard negatives. Increasing model size or adding QAT before establishing that coverage would not by itself validate fraud protection. This is an engineering inference, not a result claimed by any single source.
