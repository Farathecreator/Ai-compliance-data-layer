# Real datasets used for testing

| File | What it is | Source | Licence |
|---|---|---|---|
| `banking77_test.csv` | 3,080 real customer banking questions (77 categories) | PolyAI, Banking77, https://github.com/PolyAI-LDN/task-specific-datasets | CC BY 4.0 (attribution required) |
| `extraction_robustness_dataset.jsonl` | 569 attacks written by players trying to make a model reveal its hidden instructions | Tensor Trust benchmarks v1 (Toyer et al., 2023), https://github.com/HumanCompatibleAI/tensor-trust-data | No licence file found in the repository; confirm with the authors before redistributing |
| `hijacking_robustness_dataset.jsonl` | 775 attacks written by players trying to make a model say "Access Granted" | Tensor Trust benchmarks v1, same repository | As above |
| `bipia_text_attack_test.json` | 75 instructions designed to be hidden inside documents (15 categories), used for the development run | Microsoft BIPIA benchmark, https://github.com/microsoft/BIPIA | MIT |
| `presidio_synth_dataset_v2.json` | 1,500 synthetic sentences with every personal-data value labelled (names, addresses, cards, IBANs, phone numbers, nationality, religion or political group and more). Used to measure the compliance data layer: 500 for development, 1,000 held out | Microsoft Presidio research, https://github.com/microsoft/presidio-research (`data/synth_dataset_v2.json`, commit 7f568b6) | MIT |
| `bipia_text_attack_train.json` | 75 further hidden-document instructions with no overlap, kept unseen for the final run | Microsoft BIPIA benchmark, same repository | MIT |

## References

[1] I. Casanueva, T. Temčinas, D. Gerz, M. Henderson and I. Vulić, “Efficient intent detection with dual sentence encoders,” in *Proc. 2nd Workshop on NLP for Conversational AI (NLP4ConvAI), ACL*, 2020. Dataset: Banking77, CC BY 4.0.

[2] S. Toyer, O. Watkins, E. A. Mendes, J. Svegliato, L. Bailey, T. Wang, I. Ong, K. Elmaaroufi, P. Abbeel, T. Darrell, A. Ritter and S. Russell, “Tensor Trust: Interpretable prompt injection attacks from an online game,” in *Proc. International Conference on Learning Representations (ICLR)*, 2024. arXiv:2311.01011. Data released by the authors at tensortrust.ai/paper; no licence statement found.

[3] J. Yi, Y. Xie, B. Zhu, E. Kiciman, G. Sun, X. Xie and F. Wu, “Benchmarking and defending against indirect prompt injection attacks on large language models,” in *Proc. ACM SIGKDD Conference on Knowledge Discovery and Data Mining (KDD)*, 2025, doi: 10.1145/3690624.3709179. arXiv:2312.14197. Code and data: MIT licence.

[4] Microsoft, "Presidio research: evaluation and data generation for PII detection," GitHub repository, 2026. [Online]. Available: github.com/microsoft/presidio-research. MIT licence.

[5] Allied Irish Banks, “A guide to fees and charges for personal accounts,” AIBM/REG1 07/26, 1 July 2026. [Online]. Available: aib.ie

## Bank documents

`data/policies_aib/` holds wording taken from AIB's public pages:
- A guide to fees and charges for personal accounts, 1 July 2026 (AIBM/REG1 07/26), aib.ie
- How do I report my AIB card(s) as lost or stolen?, aib.ie/help-centre
- Make a Complaint, aib.ie/help-and-guidance

The prototype is a demo and is not affiliated with or endorsed by AIB. `planted_partner_offers.md` is a test page written for this project. It is not from AIB, and it is left out of the real-data runs.

## What stays fictional

Customer records (`data/customers.json`) and the people, numbers and keys in `data/compliance_scenarios.json` are invented. Real customer data can't be used under GDPR.
