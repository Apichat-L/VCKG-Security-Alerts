# Evaluation of context-aware vulnerability prioritization scores (literature catalogue for the EVS evaluation)

Scope note: the notes target the EVS / blast-radius evaluation in this repo (`docs/evaluation.md`: Part A ladder L0 CVSS base → L1 +CR/IR/AR → L2 +MAV → L3 +E (alert/KEV/SSVC) → L4 +P(u) = EVS; Part B blast-radius variants B0–B5). Items marked **[fetched]** were read in full text or on the primary page during this session. Items marked **[citation-known]** are standard references I cite from bibliographic knowledge without re-reading them this session. The report writer should verify the exact numbers in those before quoting them.

---

## Q1. How were the major scores (EPSS, EE, exploit-prediction, CVSS/SSVC, vendor scores, KG/graph prioritizers) evaluated: ground truth, metrics, baselines?

### Takeaway
Exploit-likelihood scores (EPSS, EE, Bozorgi, Sabottke) are judged against observed exploitation or exploit-availability labels. They report precision/recall renamed "efficiency/coverage", the "effort" share of CVEs prioritized, PR-AUC, and calibration, with CVSS base thresholds as the standard strawman baseline. Graph and KG asset-context prioritizers (VulRG and similar) mostly use case studies, published scenario re-runs and topology-perturbation tests, with qualitative or rank comparisons against CVSS/EPSS and prior methods. They rarely use an outcome label. SSVC is evaluated on inter-rater agreement, not outcomes.

### Cited Findings

**EPSS v3 (Jacobs, Romanosky, Suciu, Edwards, Sarabi, 2023) [fetched]**
- Ground truth: daily boolean exploitation-activity time series aggregated from IDS/IPS, honeypot and sensor vendors (e.g., Fortiguard, AlienVault OTX, GreyNoise, Shadowserver), Jul 2016 – Dec 2022. That is 6.4M observations over 12,243 CVEs, with 6.4% of 192,035 published CVEs observed exploited. The label is "exploitation activity in the next 30 days", a window chosen to match enterprise patch cycles — [Jacobs et al., arXiv:2302.14172 (2023)](https://arxiv.org/abs/2302.14172)
- KEV, Project Zero and ZDI "exploited" lists are included as binary *features* (past exploitation), while the label comes from sensor telemetry. This is one way EPSS separates label from input — [Jacobs et al. 2023](https://arxiv.org/abs/2302.14172)
- Forward-in-time evaluation: the final model was trained on CVEs from 1 Nov 2021 to 31 Oct 2022. It scored the state on 1 Dec 2022 and was judged on exploitation observed in the following 30 days (to 30 Dec 2022) — [Jacobs et al. 2023](https://arxiv.org/abs/2302.14172)
- Metrics: precision ("efficiency": of what you remediate, how much was exploited), recall ("coverage": of what was exploited, how much you remediated), and "effort" (% of all CVEs prioritized). Also PR-curve AUC, F1-optimal thresholds, Brier score (0.0162) and a calibration plot — [Jacobs et al. 2023](https://arxiv.org/abs/2302.14172)
- Baselines and results: EPSS v3 had PR-AUC 0.7795 and F1 0.728. At threshold 0.36 it reached 78.5% efficiency and 67.8% coverage at 3.5% effort. EPSS v2 had AUC 0.4288, EPSS v1 0.2998, and CVSS v3 base 0.051 (at its F1 threshold of ≥9.7: 6.5% efficiency, 32.3% coverage, 13.7% effort) — [Jacobs et al. 2023](https://arxiv.org/abs/2302.14172)
- Simple single-rule strategies are reported as effort/coverage/efficiency points, a cheap-baseline pattern worth copying:

  | Strategy | Effort | Coverage | Efficiency |
  |---|---|---|---|
  | CVSS PR:N | 70.4% | 88.1% | 5.1% |
  | Exploit-DB exploit exists | 10.9% | 34.7% | 13.0% |
  | "Code Execution" tag | 17.2% | 48.0% | 11.4% |
  | CWE-119 | 6.2% | 16.9% | 11.1% |
  | Metasploit module | 1.0% | 14.9% | 60.5% |
  | In KEV | 0.5% | 5.9% | 53.2% |

  — [Jacobs et al. 2023](https://arxiv.org/abs/2302.14172)
- The authors acknowledge that sensor-based labels have class- and feature-dependent noise (e.g., signature-based IDS coverage bias) — [Jacobs et al. 2023](https://arxiv.org/abs/2302.14172)
- Earlier EPSS work introduced the efficiency/coverage framing and compared remediation strategies (CVSS thresholds, exploit-DB rules) against a model **[citation-known]** — [Jacobs, Romanosky, Adjerid, Baker, "Improving vulnerability remediation through better exploit prediction", Journal of Cybersecurity 6(1), 2020](https://doi.org/10.1093/cybsec/tyaa015); [Jacobs et al., "Exploit Prediction Scoring System (EPSS)", Digital Threats: Research and Practice 2(3), 2021](https://doi.org/10.1145/3436242)

**Expected Exploitability (Suciu, Nelson, Lyu, Bao, Dumitraș, USENIX Security 2022) [fetched]**
- Ground truth: functional-exploit evidence aggregated from many sources. These include the CVSS Temporal "Functional/High" exploit-code-maturity values collected from IBM X-Force and Tenable (28,009 CVEs), commercial exploitation tools (Metasploit, Canvas, D2; 2,547 CVEs) and Bugtraq exploit pages. Evidence is dropped if it can't be confirmed within one year of disclosure, "simulating a historical setting". Total: 32,093 positive CVEs out of 103,137 — [Suciu et al., USENIX Sec 2022 / arXiv:2102.07869](https://arxiv.org/abs/2102.07869); [USENIX page](https://usenix.org/conference/usenixsecurity22/presentation/suciu)
- Label noise is treated explicitly. Exploits published after the collection window become false negatives. The authors test for *feature-dependent* noise by comparing 12 ground-truth sources across vulnerability types and products, and train with noise-robust losses (e.g., Forward Correction) — [Suciu et al. 2022](https://arxiv.org/abs/2102.07869)
- Deployment-style temporal evaluation: the data is split temporally, the classifier is retrained periodically on history available at that time, and the last year of disclosures is excluded from training because their positive labels may not exist yet. The authors found retraining every 6 months was needed. Testing simulates streaming, recomputing features as artifacts appear — [Suciu et al. 2022](https://arxiv.org/abs/2102.07869)
- Metrics and baselines: precision at 0.8 recall and PR-AUC, compared with CVSSv2/v3 Exploitability, EPSS and prior exploit classifiers. The headline result is that precision rises from 49% to 86% over existing metrics — [Suciu et al. 2022](https://arxiv.org/abs/2102.07869)
- The same paper shows CVSS Exploitability has very poor precision at capturing exploitability (its Fig. 3) and that many PoCs appear before CVSS scores are published. This is a timeline argument for evaluating scores *as of* a point in time — [Suciu et al. 2022](https://arxiv.org/abs/2102.07869)

**Earlier exploit prediction**
- Sabottke, Suciu, Dumitraș, "Vulnerability Disclosure in the Age of Social Media: Exploiting Twitter for Predicting Real-World Exploits", USENIX Security 2015 (pp. 1041–1056). It is an SVM on Twitter features (Feb 2014 – Jan 2015). Real-world exploit ground truth draws on Symantec anti-virus and intrusion-protection signature descriptions plus vulnerability databases and Microsoft advisories. The paper names class imbalance, data scarcity and ground-truth bias as the core challenges and also studies adversarial manipulation of the features — [USENIX biblio](https://www.usenix.org/biblio/vulnerability-disclosure-age-social-media-exploiting-twitter-predicting-real-world-exploits); [PDF](https://www.umiacs.umd.edu/%7Etdumitra/papers/USENIX-SECURITY-2015.pdf)
- Bozorgi, Saul, Savage, Voelker, "Beyond Heuristics: Learning to Classify Vulnerabilities and Predict Exploits", KDD 2010. It uses an SVM on OSVDB/CVE text and metadata, labelled by exploit existence in OSVDB, with offline and time-ordered online (train on past, test on future) evaluations, and argues that CVSS-style heuristics poorly predict exploitation **[citation-known]** — [ACM DL](https://doi.org/10.1145/1835804.1835821)
- Allodi & Massacci, "Comparing Vulnerability Severity and Exploits Using Case-Control Studies", ACM TISSEC 17(1), 2014. It uses Symantec attack-signature data (exploits in the wild) as ground truth and a case-control design that controls for confounders. It reports the risk reduction from patching CVSS-high vs. exploit-DB-listed vulnerabilities and finds CVSS a poor predictor of in-the-wild exploitation **[citation-known]** — [ACM DL](https://doi.org/10.1145/2630069)

**CVSS (v3/v4, CVSS-BT) and SSVC**
- SSVC v1 was evaluated by a tabletop inter-rater agreement pilot rather than outcome accuracy. Six raters (five authors and one outside analyst, most with ≥1 year as vulnerability analysts) scored 9 CVEs from both supplier and deployer perspectives (108 decision sets). Information was held constant via standardized scenarios, and Fleiss' κ was computed per decision point and per decision path. Per-point κ: Exploitation 0.807, Technical Impact 0.679, Exposure 0.480, Portfolio Value 0.257, Mission Impact 0.146, Safety Impact 0.122. Path-level κ: supplier 0.226, deployer 0.295. The authors report a "disagreement range" because κ ignores ordering, and call the result "encouraging, though not conclusive" — [CERT/CC SSVC docs, "Evaluation of the Draft Trees"](https://certcc.github.io/SSVC/topics/evaluation_of_draft_trees)
- CVSS scoring reliability has been evaluated with human-subject studies. Wunder et al. surveyed 196 CVSS users with a ~9-month follow-up of 59 participants and found Attack Vector, User Interaction and Scope inconsistently scored. About one third applied Changed Scope regardless of vulnerability type — [Wunder, Kurtz, Eichenmüller, Gassmann, Benenson, IEEE S&P 2024, pp. 1102–1121](https://arxiv.org/abs/2308.15259); [FAU project page](https://www.cs1.tf.fau.de/research/human-factors-in-security-and-privacy-group/consistency-of-cvss/)
- Sources disagree on the follow-up figure: one secondary report says 68% of users gave different severities for the same vulnerability, while the FAU page gives 35–55% — [Schneier summary](https://www.schneier.com/blog/archives/2023/09/inconsistencies-in-the-common-vulnerability-scoring-system-cvss.html) vs. [FAU](https://www.cs1.tf.fau.de/research/human-factors-in-security-and-privacy-group/consistency-of-cvss/)
- Allodi, Cremonini, Massacci, Shim measured CVSS v3 scoring accuracy as agreement with scores set by FIRST SIG experts, comparing MSc students and professionals (median 6 years' experience). Security competence improved accuracy, but professionals had no clear edge over security-specialised students — [Empirical Software Engineering 25(2), 2020, 1063–1094](https://doi.org/10.1007/s10664-019-09797-4)

**Cross-system outcome comparison (CVSS vs EPSS vs SSVC vs MS Exploitability Index)**
- Koscinski, Nelson, Okutan, Falso, Mirakhorli, "Conflicting Scores, Confusing Signals: An Empirical Study of Vulnerability Scoring Systems", arXiv:2508.13644 (2025) — [arXiv](https://arxiv.org/html/2508.13644v1)
  - Design: 600 Microsoft Patch Tuesday CVEs (Apr–Jul 2024), KEV as the outcome label (only 13 of 600 in KEV), and SSVC assigned manually by a security team, giving three Mission-and-Well-Being variants.
  - Metrics: Kendall τ, Spearman ρ and Pearson between systems; Cohen's κ and Krippendorff's α on binned scores; "triage workload" (count in the top 1/2/3 bins); top-N overlap; and the score distribution of KEV CVEs.
  - Leakage control for EPSS: monthly EPSS snapshots (May 2021 – Dec 2024) for all 1,226 KEV CVEs, with any score generated after the KEV-add date dropped.
  - Results: inter-system κ was about −0.01 to 0.03 and α −0.59 to 0.00. Only 5 CVEs appeared in all four top-100 lists, and CVSS gave the same score to 198 CVEs in its top 20. Only 19.9% of KEV CVEs had EPSS > 0.5 before listing, 8.3% > 0.9, and 22.4% had no EPSS score before exploitation.

**Graph / KG / asset-context prioritizers**
- VulRG (Jiang, Oo, Meng, Lim, Sikdar; NUS and NCS; arXiv:2502.11143, Feb 2025) — [arXiv](https://arxiv.org/abs/2502.11143)
  - Method: combines a network communication graph (attack paths to critical assets) with a system dependency graph (risk propagation), mixing CVSS likelihood, EPSS and known-exploit presence with asset criticality.
  - Evaluation: no outcome labels. The authors ran a systematic literature review (265 papers after deduplication) to find prior prioritization papers that validated on real-world systems *and* published their topology/configuration. They re-ran three of those scenarios (OpenPLC, an enterprise network, an ICS/SCADA network), compared the resulting patch rankings with the published methods (partly re-implemented), and showed rankings changing under a network change (NP-1 vs NP-2, removing a VPN–DC link).
  - Explainability is shown by per-CVE walk-throughs.
- Jiang et al. also published a survey of 82 vulnerability-prioritization studies with a taxonomy of severity, exploitability, contextual, predictive and aggregation metrics. They report "significant gaps" and call for context-aware metrics and a framework for evaluating prioritization methods — [Jiang, Oo, Meng, Lim, Sikdar, arXiv:2502.11070 (2025)](https://arxiv.org/abs/2502.11070)
- Bulut, Adebayo, Sow, Ocepek (IBM), "Vulnerability Prioritization: An Offensive Security Approach", arXiv:2206.11182 (2022). The pentest-inspired prioritization uses asset environmental factors (public vs private networking, criticality). It is evaluated with "a real world case study for a large client" plus an ML accuracy assessment, and the abstract does not give metrics or baselines — [arXiv](https://arxiv.org/abs/2206.11182)
- CAVP (context-aware vulnerability prioritization model) was tested on 720 NVD vulnerability announcements and reports that context information improved prioritization. I only saw the ResearchGate snippet, so the year, venue and metrics are unverified — [ResearchGate](https://www.researchgate.net/publication/358547679_CAVP_A_context-aware_vulnerability_prioritization_model)
- A 2026 Computers & Security article, "Decision-oriented vulnerability prioritization via context-aware probabilistic risk estimation", combines CVSS with asset criticality, Internet exposure, exploit availability, business impact and temporal information, and claims substantial improvement over CVSS. The full text returned 403, so the evaluation design is unverified — [ScienceDirect S0167404826002385](https://www.sciencedirect.com/science/article/abs/pii/S0167404826002385)

### Inferences
- The EPSS effort/coverage/efficiency table is the most reviewer-recognised presentation in this space. Reporting each EVS ladder rung (L0–L4) and each single-signal rule (in KEV, Metasploit exists, Internet-reachable, CR=H) as an effort/coverage/efficiency point on the lab's labelled pairs fits Part A directly and is cheap.
- Asset/graph prioritizers (VulRG and similar) set a low bar: case studies plus "rankings move when topology changes". A lab with real pentest outcomes, even a few dozen labels, is already stronger evidence than most graph-prioritization papers present. That is worth saying explicitly in the paper.
- VulRG's NP-1 vs NP-2 topology perturbation is a cheap *metamorphic test* for blast radius (Part B). Remove or add a `CONNECTS_TO` / `ALLOWED_TO_REACH` edge and check that BR and P(u) change in the predicted direction and only for the affected assets.

### Gaps
- I did not retrieve EPSS v4 (released 2025) evaluation details, the CVSS v4 / CVSS-BT validation, Tenable VPR or Qualys TruRisk methodology papers. As far as I know, the vendor scores publish no peer-reviewed outcome evaluation, only marketing claims, but I did not verify that this session. CVSS-BT is a community project (github.com/t0sche/cvss-bt) that enriches CVSS with KEV/EPSS/exploit sources, and I found no formal evaluation of it.
- Nagaty et al. (the unified CTI KG this project replicates; see `docs/schema.md`) did not surface in web search, so its evaluation design is not covered here. It should be taken from the PDF in the repo.
- I found no peer-reviewed paper that evaluates a KG-based asset-context score against pentest outcomes on a small lab. This looks like a genuine gap, and it may be a contribution claim for EVS.

---

## Q2. How do papers avoid circularity when the score uses KEV/exploit features and the label is also KEV/exploit?

### Takeaway
Four techniques are used: (1) split label and feature sources (EPSS uses sensor telemetry as the label and KEV only as a feature); (2) as-of-time evaluation, scoring with information available at t and labelling with events in (t, t+Δ]; (3) temporal train/test splits with periodic retraining and exclusion of the most recent, label-incomplete window (EE); (4) dropping any feature snapshot produced after the label event (Koscinski et al. drop EPSS scores taken after the KEV add date).

### Cited Findings
- EPSS separates sources. Past-exploitation lists (KEV, Project Zero, ZDI) are binary input features, while the predicted target is exploitation *activity* from sensor telemetry in the next 30 days after the scoring date — [Jacobs et al. 2023](https://arxiv.org/abs/2302.14172)
- EPSS v3 is evaluated forward in time: trained on Nov 2021 – Oct 2022, scored on 1 Dec 2022, labelled from 1–30 Dec 2022 — [Jacobs et al. 2023](https://arxiv.org/abs/2302.14172)
- EE uses temporal splits with retraining on all history available at each point and excludes the last year of disclosures from training because labels are not yet observable. Exploit evidence not confirmed within one year of disclosure is dropped to simulate a historical setting — [Suciu et al. 2022](https://arxiv.org/abs/2102.07869)
- Koscinski et al. keep only EPSS scores generated *before* a CVE's KEV-addition date when asking whether EPSS anticipated exploitation — [arXiv:2508.13644](https://arxiv.org/html/2508.13644v1)
- General ML-security guidance names temporal and spatial bias ("time travel": training or feature data from after the test point) and label inaccuracy as leading pitfalls, and recommends time-aware splits **[citation-known]** — [Pendlebury et al., "TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time", USENIX Security 2019](https://www.usenix.org/conference/usenixsecurity19/presentation/pendlebury); [Arp et al., "Dos and Don'ts of Machine Learning in Computer Security", USENIX Security 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/arp)
- In this repo, `docs/evaluation.md` already sets L3 = L2 in the KEV-forward test because SSVC `active` would leak the label. Pentest grades are deliberately not derived from CR/IR/AR, an input of L1–L4. Both are consistent with the techniques above — local file `docs/evaluation.md`

### Inferences
- For EVS rung L3 (E from KEV/SSVC/alert), legitimate designs are:
  - **(a) KEV-forward:** freeze KEV, SSVC and exploit-DB at date T0, score, then label with KEV additions after T0 (the project already does this; memory notes it is underpowered on the lab).
  - **(b) Held-out feature:** when the label is KEV, report L3 with E from exploit-DB/Metasploit only (no KEV), and vice versa.
  - **(c) Independent outcome label:** use the pentest outcome (A1/A2), where KEV is legitimately an input because the label (did *our* team exploit it here) is a different event.
- Alert-derived E = H, where an alert reports c on u, is circular if the A2 label is "the pentest generated that alert". An ablation should report L3 with alert-based E removed (KEV/SSVC only) when scoring A2 scenarios.

### Gaps
- I found no paper that discusses circularity for *environment-local* labels, such as an internal pentest or alert telemetry used as both feature and label. Arguments for this case have to be built by analogy.

---

## Q3. How do context/asset-aware prioritization evaluations show that adding asset context helps (expert panels, analyst studies, case studies, red team, simulated environments)? Inter-rater agreement?

### Takeaway
Most asset-context work validates with (i) case studies or worked examples on a real or published topology, (ii) re-runs of published scenarios with rank comparison against prior methods, (iii) perturbation or what-if tests on topology, and (iv) synthetic stress tests with weight sensitivity. Outcome-based validation (pentest, red team, incidents) is rare. Expert labels are judged with Fleiss' κ or Cohen's κ, Krippendorff's α, and rank correlation (Kendall τ, Spearman ρ).

### Cited Findings
- VulRG validates context by re-running three published scenarios (OpenPLC, enterprise, ICS), comparing rankings with re-implemented prior methods, and showing rank changes under topology modification — [arXiv:2502.11143](https://arxiv.org/abs/2502.11143)
- PECR (Alam 2026) is an explicitly synthetic stress test:
  - Data: 100 synthetic vulnerability–asset records on 62 role-consistent assets, with 30 generator replications.
  - Sensitivity: 30,000 Dirichlet weight draws (broad, moderate and narrow) and masking of 10% of factor cells to flag "evidence-limited" decisions.
  - Baselines: CVSS-only, EPSS-only, KEV-first, CVSS×EPSS and a five-factor "context-lite" comparator, scored by Kendall τ against the full ordering. Results: τ = 0.196, 0.221, 0.301, 0.234 and 0.755. Median τ under perturbation was 0.836, 0.893 and 0.924.
  - The paper states that this does **not** establish predictive accuracy or production effectiveness.

  — [Alam, arXiv:2608.03110 (2026)](https://arxiv.org/abs/2608.03110)
- IBM's offensive-security prioritization (asset networking public/private and criticality) was evaluated by an industrial case study for one large client — [Bulut et al., arXiv:2206.11182](https://arxiv.org/abs/2206.11182)
- Agreement statistics in this area include SSVC's Fleiss κ per decision point and per path, plus a disagreement range to capture ordinal distance — [CERT/CC SSVC](https://certcc.github.io/SSVC/topics/evaluation_of_draft_trees). Koscinski et al. used Cohen's κ, Krippendorff's α and Kendall/Spearman — [arXiv:2508.13644](https://arxiv.org/html/2508.13644v1)
- Human-subject reliability designs include a large online survey with a delayed re-test of the same participants (test–retest consistency) — [Wunder et al. S&P 2024](https://arxiv.org/abs/2308.15259) — and accuracy against an expert reference (FIRST SIG scores), stratified by expertise — [Allodi et al. EMSE 2020](https://doi.org/10.1007/s10664-019-09797-4)
- An LLM-as-triager line of work also exists ("Prompting the Priorities: A First Look at Evaluating LLMs for Vulnerability Triage and Prioritization", arXiv:2510.18508). I saw only the search result, so its design is unverified — [arXiv](https://arxiv.org/html/2510.18508v1)

### Inferences
Mapping to the EVS evaluation:
- **Part A ladder, rung by rung:**
  - L1 (CR/IR/AR): needs an *independent* criticality judgement, from expert ranking or pentest "data_access/pivot" grade, never the CR/IR/AR inputs themselves.
  - L2 (MAV): checkable by pentest reachability (could the attacker reach it from the Internet zone).
  - L3 (E): checkable by KEV-forward or by the pentest exploit outcome.
  - L4 (P(u)): checkable by whether a pivot or data access was achieved from u (A2 grade 3).
- **Part B variants:**
  - VulRG-style topology perturbation (metamorphic tests).
  - PECR-style weight-sensitivity sweeps (β, γ, k). `score_kg sensitivity` already exists; adding Dirichlet or random weight draws plus Kendall τ distribution percentiles would match PECR's presentation.
  - "Context-lite" comparators, i.e. ablations that drop one signal.
- **Expert panel (small lab):** 3–5 raters (lab staff, pentesters, or students with a security specialisation, per Allodi et al.) rank or grade a stratified sample of 30–60 (asset, CVE) pairs. Report Fleiss κ (graded) or Kendall's W (rankings), then evaluate L0–L4 by NDCG/Kendall τ against the consensus. Hold scenario information constant, as SSVC did. Keep the ratings independent before discussion (two-stage: independent, then a Delphi-style discussion round).

### Gaps
- I found no peer-reviewed red-team or CyberRange evaluation of an asset-context vulnerability score with quantitative outcome metrics. Commercial claims (e.g., Persistent "Threat KG") are unverified marketing.
- I did not locate the source of a "384 experts, >3000 vulnerabilities" survey snippet that appeared next to CAVP. It is unverified and should not be cited.

---

## Q4. What evaluation designs are accepted when ground truth is scarce?

### Takeaway
The accepted toolbox is: inter-rater-agreement pilots (SSVC); expert-reference accuracy (Allodi); case studies and published-scenario re-runs (VulRG, IBM); synthetic stress tests with weight-sensitivity and missing-data tests (PECR); cross-system agreement analysis (Koscinski); and a simple rule-strategy effort/coverage table (EPSS). Each paper that uses them states its limits explicitly. None of them alone claims predictive accuracy.

### Cited Findings
- The SSVC pilot design holds scenario information constant and runs independent decisions, then a group discussion. It reports κ per decision and per path, with an explicit statement that more diverse raters are needed — [CERT/CC](https://certcc.github.io/SSVC/topics/evaluation_of_draft_trees)
- PECR uses synthetic records, replications, Dirichlet weight perturbations, missing-evidence masking and Kendall τ versus single-signal baselines, and explicitly disclaims predictive accuracy — [arXiv:2608.03110](https://arxiv.org/abs/2608.03110)
- Koscinski et al. combine a cross-system agreement study (κ, α, τ) with a small outcome subset (13 KEV CVEs), plus a "triage workload" metric (items in the top bins) and a ties analysis — [arXiv:2508.13644](https://arxiv.org/html/2508.13644v1)
- EPSS reports single-rule strategies as effort/coverage/efficiency points, a baseline set that needs no model — [Jacobs et al. 2023](https://arxiv.org/abs/2302.14172)
- Graded-relevance ranking metric NDCG **[citation-known]** — [Järvelin & Kekäläinen, "Cumulated gain-based evaluation of IR techniques", ACM TOIS 20(4), 2002](https://doi.org/10.1145/582415.582418)

### Inferences
Candidate designs for a small lab:

| Design | Ground truth | Metric | Cost | Fits |
|---|---|---|---|---|
| A1 sampled pentest (existing) | exploited yes/no per pair, stratified random draw | precision@k, NDCG@k, effort/coverage/efficiency per rung, bootstrap CIs | about 1 h/pair; 20–60 pairs feasible | Part A rungs L0–L4 |
| A2 scenario pentest (existing) | graded outcome 0–3 | NDCG per scenario, averaged | medium | L4 (pivot/data access validates P(u)) |
| KEV-forward | KEV adds after a freeze date | coverage/efficiency, PR-AUC | free, but few positives in a lab's ~300 pairs | L3 (with held-out feature) |
| Expert ranking panel | 3–5 raters on 30–60 pairs | Kendall's W / Fleiss κ for agreement; Kendall τ / NDCG of L0–L4 vs consensus | a few person-hours | L1, L2 (asset value, exposure) |
| Pairwise comparison (expert) | "which of these two should be fixed first" | Bradley–Terry ranking; % agreement of score with majority | cheap per item; scales to more pairs | L1–L4, especially close calls where CVSS ties |
| Rule-strategy table | same labels as A1/KEV | effort/coverage/efficiency | free | baseline row for Part A |
| Sensitivity / Dirichlet weights | none | distribution of Kendall τ vs default; rank-flip counts | free | Part B (β, γ, k) |
| Topology metamorphic tests | predicted direction of change | pass/fail per perturbation | free | Part B (B0–B5) |
| Synthetic scenario injection | injected (asset, CVE, path) with known intended rank | rank of injected item | low | Part B, plus L4 sanity |
| Cross-system agreement | none | τ, κ, top-N overlap vs CVSS, EPSS, SSVC | free | context for reviewers: how much EVS reorders |

- The table's design choices draw on the cited works above. The pairwise / Bradley–Terry option is my suggestion; I did not find a vulnerability-prioritization paper using it this session.
- CVSS ties are a central practical argument. Koscinski et al. found 198 CVEs tied in the CVSS top-20, so reporting how many ties EVS breaks (L0 vs L4) and whether the tie-breaks agree with pentest or expert labels is cheap and persuasive.
- Bootstrap CIs on tiny label sets are needed. The repo's current preliminary run shows NDCG@10 = 1.000 ceiling effects on 4–6 labels. Reviewers will expect stating minimum detectable effects or presenting the result as a case study rather than a significance claim.

### Gaps
- I did not retrieve a peer-reviewed Delphi or analyst triage user study specifically for vulnerability prioritization (beyond SSVC and the CVSS human-subject studies). This may exist in HCI or SOC venues (e.g., SOUPS); it was not searched.

---

## Q5. Reviewer critiques of weak evaluations; what reviewers expect

### Takeaway
Recurring critiques cover proxy ground truth (KEV is incomplete and biased), label noise and bias in exploit data, temporal leakage, coarse scores with many ties, overloaded top bins, lack of outcome linkage, and case-study-only validation. Reviewers expect outcome-linked metrics (exploit capture rate, workload reduction), temporal hygiene, strong simple baselines (CVSS, EPSS, KEV-first) and honest disclaimers when the evidence is synthetic or case-based.

### Cited Findings
- Koscinski et al. call KEV a binary, imperfect proxy that does not reflect exploitability in every environment. They note that ties inflate top-N results and that binning affects κ/α. They recommend context-aware systems evaluated on operational measures: time-to-remediation, workload reduction, exploit capture rate — [arXiv:2508.13644](https://arxiv.org/html/2508.13644v1)
- EE argues that exploit ground truth has class- and feature-dependent label noise that can "derail" learning, and that late-published exploits create false negatives — [Suciu et al. 2022](https://arxiv.org/abs/2102.07869)
- EPSS warns that aggregating multiple exploit sources does not give uniform label coverage across vulnerability types — [Jacobs et al. 2023](https://arxiv.org/abs/2302.14172)
- SSVC's own authors warn that author-raters inflate agreement and that κ is only comparable across decision points with the same number of options — [CERT/CC](https://certcc.github.io/SSVC/topics/evaluation_of_draft_trees)
- PECR disclaims predictive accuracy for synthetic evaluation, which reviewers expect in place of over-claiming — [arXiv:2608.03110](https://arxiv.org/abs/2608.03110)
- CVSS environmental and base inputs are themselves unreliable between raters (AV, UI, Scope), which undermines any score built on hand-set CVSS metrics — [Wunder et al. S&P 2024](https://arxiv.org/abs/2308.15259)

### Inferences
Likely reviewer questions for EVS, and answers already available or cheap to add:
- **"Isn't L3 circular with KEV?"** Answer with KEV-forward, a held-out-feature variant, and a pentest label that is independent of KEV.
- **"Are CR/IR/AR just your opinion?"** Show a justification column and an independent expert panel agreement (κ) on CR/IR/AR, and evaluate L1 against pentest grades that never use CR/IR/AR (already the design).
- **"n is tiny."** Report bootstrap CIs, effect sizes and a power note. Frame Part A as a case study with sampled (not cherry-picked) targets, and keep A1 (random draw) apart from A1s (hand-picked), as already done.
- **"Does it beat EPSS / KEV-first, not just CVSS?"** Include EPSS, KEV-first, CVSS×EPSS and Metasploit-exists as Part A baselines, as in the EPSS and PECR baseline sets.
- **"Is β/γ/k tuned on the test set?"** Fix them a priori (already β=0.5, γ=0.5, k=1) and show a sensitivity sweep.
- **"Does blast radius matter?"** Part B ground-truth measurement plus metamorphic topology tests, with B0 as the ablation.

### Gaps
- I found no published reviewer reports (e.g., OpenReview) for vulnerability-prioritization papers. The critiques above are inferred from the authors' own limitations sections and from cross-system studies.
