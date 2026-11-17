# Small-sample statistics and experimental design for evaluating EVS and the blast radius against weak, small or partial ground truth

Context read for tailoring (not modified): `evaluation/README.md`, `docs/evaluation.md`, `eval_kg/metrics.py`, `eval_kg/ladder.py`, `eval_kg/variants.py`. Current state relevant to these notes:
- A1 has about 6 labelled (asset, CVE) pairs with 1 exploited. L0 to L4 all tie at NDCG@10 = 1.000 (ceiling effect). L4 − EPSS ΔNDCG@10 = +0.500, 95% CI [+0.000, +0.613].
- A3 (forward-in-time KEV) has about 2 positives and flags itself as underpowered below 5 positive CVEs.
- `pentest_candidates.csv` is a stratified random sample (zone × CVSS band × exploit-available, seed 7), and every row already records its inclusion probability. This makes design-based (Horvitz–Thompson) estimation possible.
- `not_tried` rows are dropped from A1.
- KEV and SSVC feed E in L3. Labels that come from KEV are therefore circular for L3 and L4, except in the forward-in-time A3 design.
- `metrics.paired_bootstrap` uses a percentile CI, resamples items when there are fewer than 5 scenarios, and skips resamples in which NDCG is undefined (no positive). Skipping these silently conditions the CI on "at least one positive drawn".

---

## Q1. Ranking metrics for few positives and graded relevance: which to pick and why

### Takeaway
With 1 to 10 positives, report metrics that are interpretable per positive. These are: the rank of each positive (or "negatives ranked above each positive"), AP (AUC-PR), and recall/effort at fixed budgets (the EPSS-style efficiency/coverage, or "work saved over random"). Report each next to its random-ranking expectation. NDCG@k and P@k on a list of 6 items with 1 positive hit the ceiling and should be reported only as secondary metrics. Use RBO or Kendall τ-b to describe how much each ladder step reorders the full list. These need no labels, so they count as sensitivity evidence, not evidence of validity.

### Cited Findings
- On imbalanced data, the PR plot is more informative than the ROC plot. ROC can give a misleadingly optimistic picture because specificity is dominated by the many negatives. — [Saito & Rehmsmeier 2015, PLoS ONE 10(3): e0118432](https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0118432) (also [PMC4349800](https://pmc.ncbi.nlm.nih.gov/articles/PMC4349800))
- EPSS defines **efficiency** = precision (exploited among the items flagged for remediation) and **coverage** = recall (flagged among all exploited). It compares strategies by plotting efficiency against coverage at different thresholds, and by "effort" (how many items must be remediated) at matched coverage. — [Jacobs et al., "Exploit Prediction Scoring System (EPSS)", arXiv 1908.04856](https://arxiv.org/pdf/1908.04856); [EPSS v3, Jacobs et al., arXiv 2302.14172](https://arxiv.org/abs/2302.14172)
- Secondary coverage of EPSS v3 reports about 78.5% efficiency and 67.8% coverage at its best threshold, against 6.5% and 32.3% for CVSS v3.x. The original EPSS table shows an effort reduction of about 85.9% at matched coverage against a CVSS 10 cutoff (432 down to 61). These are threshold- and dataset-dependent and cannot be compared directly across studies. — [Dark Reading summary](https://www.darkreading.com/vulnerabilities-threats/machine-learning-improves-prediction-of-exploited-vulnerabilities); [EPSS 2019 paper](https://arxiv.org/pdf/1908.04856). The v3 figures were not verified against the v3 PDF in this session.
- Rank-biased overlap (RBO) is a top-weighted similarity measure for indefinite or incomplete rankings that need not share all their items. It has a persistence parameter p (an "expected depth" user model), handles ties, and gives lower and upper bounds plus an extrapolated point estimate when lists are truncated. — [Webber, Moffat & Zobel 2010, ACM TOIS 28(4), "A Similarity Measure for Indefinite Rankings"](https://people.eng.unimelb.edu.au/ammoffat/abstracts/wmz10acmtois.html) (DOI 10.1145/1852102.1852106)
- AUC has a probabilistic meaning: the probability that a randomly chosen positive is scored above a randomly chosen negative (the 2AFC interpretation). — [Hanley & McNeil 1982, Radiology 143(1):29–36](https://math.ucdavis.edu/~saito/data/roc/hanley-mcneil-auc.pdf)
- infAP (inferred AP) estimates average precision from a random subsample of judgments. On a 100% sample it equals AP. In TREC experiments it is more robust to incomplete judgments than bpref. — [Yilmaz & Aslam, CIKM 2006](https://www.khoury.northeastern.edu/home/jaa/papers/AslamYi06.pdf); [Yilmaz, Kanoulas & Aslam / KAIS 16 (2008) 173–211](https://datalearner.com/academic/journal-papers/0219-1377/volumes-and-issues/16/paper-detail/15917); [NIST TRECVID infAP page](https://www-nlpir.nist.gov/projects/tv2006/infAP.html)

### Inferences
- **Recommended primary metric set for A1 and A3 (binary relevance, few positives):**
  1. **Rank of each positive** and **AUC = fraction of labelled negatives ranked below each positive**. With n₊ = 1, AUC is exactly (number of negatives below the positive) / n₋, so it is transparent and cannot hide anything.
  2. **AP** (sklearn `average_precision_score`), shown next to its random-ranking baseline ≈ prevalence n₊/n. AP is the area under the PR curve and is preferred over ROC-AUC under imbalance (Saito & Rehmsmeier).
  3. **Effort-to-coverage**: the number of items an analyst must work through, in score order, to reach 50% / 100% of the positives. Compare it with the random expectation (for 1 positive among n items, the expected rank is (n+1)/2). **Work saved over random** = 1 − effort_scorer / effort_random. This is the EPSS framing, which practitioners and reviewers in vulnerability management recognise.
  4. P@k and recall@k only at k values that match a real operating budget (for example "the top 10 a SOC patches this week"), and always together with k/n.
- **Graded A2 labels (0–3)**: keep NDCG@k with gain 2^g − 1, as the project does. Also report the mean grade of the top-k and Kendall τ-b between score and grade (τ-b corrects for the many ties in the grades). On lists this short, prefer NDCG over the full list (k = n) to NDCG@10, because @10 on ≤ 10 items is just NDCG.
- **Rank-change descriptors (no labels needed)**: for each step L(i−1)→L(i), report RBO (p ≈ 0.9 weights roughly the top 10), Kendall τ-b, and the number of items that enter or leave the top-k. They show that a step *does* something. They do not show that it *helps*. Keep them labelled as sensitivity, as `docs/evaluation.md` already says.
- **Do not report MRR as a headline metric** when there is one positive. With one positive, MRR and AP are identical, and the reciprocal ranks 1, 1/2 and 1/3 create large jumps.
- When the score ties (EVS saturating at 10, as in A2), break ties by the **expected value over random tie-breaks**, not by item id. In practice, compute the metric averaged over all permutations within tied groups, or by Monte Carlo. Under id tiebreak, the A2 "1.000" for L0–L4 is an artifact. Averaging over tie orders would show ≈ 0.5 to 0.8 instead, which is the honest value.

### Gaps
- I found no published guidance that is specific to evaluating vulnerability prioritisation with fewer than 10 positives. The recommendations above are carried over from IR and medical diagnostics.
- The EPSS v3 efficiency/coverage numbers were not checked against the v3 PDF itself.

---

## Q2. Paired comparison of two scorers on the same items, and multiple-comparison correction

### Takeaway
Every scorer ranks the *same* labelled items, so all comparisons are paired. The recipe is: (a) a paired bootstrap BCa or percentile CI on the metric *difference*; (b) a paired randomization (permutation) test that swaps the two systems' scores per unit; (c) for AUC, DeLong's test; (d) for a fixed top-k budget, exact McNemar on the discordant pairs. Correct across the ladder steps and baselines with Holm. In IR, randomization, bootstrap and t-test agree with one another. Wilcoxon and sign tests are weaker and are discouraged for comparing means.

### Cited Findings
- Smucker, Allan & Carterette compared paired t, Wilcoxon, sign, shifted bootstrap and randomization tests on TREC runs. The t, bootstrap and randomization tests largely agree. Wilcoxon and sign tests "have a poor ability to detect significance and have the potential to lead to false detections". The authors recommend the randomization (Fisher permutation) test. — [Smucker, Allan & Carterette, CIKM 2007, pp. 623–632](https://ciir-publications.cs.umass.edu/getpdf.php?id=744)
- A follow-up found that agreement among the randomization, bootstrap and t-tests decreases as the number of topics drops from 50 to 10. Small-sample conclusions are therefore more test-dependent. — [Smucker, Allan & Carterette, SIGIR 2009 "Agreement among statistical significance tests … at varying sample sizes"](https://ciir-publications.cs.umass.edu/pub/web/getpdf.php?id=885)
- Dietterich found that for algorithms that can be run only once, McNemar's test is the only one with acceptable Type I error. A difference-of-two-proportions test and a paired t-test over resampled splits had elevated Type I error. — [Dietterich 1998, Neural Computation 10(7):1895–1923](https://web.engr.oregonstate.edu/~tgd/publications/dietterich-approximate-statistical-tests-nc1998.pdf)
- Demšar recommends the Wilcoxon signed-rank test for comparing two classifiers *across multiple data sets*, and Friedman with post-hoc tests and critical-difference diagrams for more than two. — [Demšar 2006, JMLR 7:1–30](https://www.jmlr.org/papers/v7/demsar06a.html); for all-pairwise extensions with adjusted p-values see [García & Herrera 2008, JMLR 9](https://www.jmlr.org/beta/papers/v9/garcia08a.html)
- DeLong, DeLong & Clarke-Pearson give a nonparametric test for comparing correlated AUCs (two scorers on the same cases) using generalized U-statistics for the covariance. — [Biometrics 44(3):837–845, 1988, DOI 10.2307/2531595](https://www.jstor.org/stable/2531595)
- Dror et al. survey ACL/TACL 2017 and find significance testing often ignored or misused. The paired t-test was the most used even where its assumptions fail. They give a decision protocol that chooses a test from the properties of the evaluation measure (parametric tests only for measures that are roughly normal; otherwise bootstrap or permutation). — [Dror, Baumer, Shlomov & Reichart, ACL 2018, P18-1128](https://aclanthology.org/P18-1128/)
- Holm's step-down procedure controls the family-wise error rate with more power than Bonferroni. — [Holm 1979, Scand. J. Statist. 6(2):65–70](https://www.jstor.org/stable/4615733) (not fetched in this session; standard reference). It is implemented in `statsmodels.stats.multitest.multipletests(method="holm")` ([docs](https://www.statsmodels.org/stable/generated/statsmodels.stats.multitest.multipletests.html)).
- The bootstrap BCa and percentile intervals are described in [Efron & Tibshirani 1993, *An Introduction to the Bootstrap*, Chapman & Hall, DOI 10.1201/9780429246593](https://doi.org/10.1201/9780429246593) (standard reference, not fetched). SciPy implements BCa and paired resampling in [`scipy.stats.bootstrap`](https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.bootstrap.html) and paired sign-flip permutation tests in [`scipy.stats.permutation_test`](https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.permutation_test.html) with `permutation_type="samples"`.

### Inferences
- **Choosing the unit.** When the metric is per-item (indicator "positive in top-k", per-item rank contribution), use a paired permutation over items. When it is per-list (NDCG per scenario), resample scenarios. With fewer than 5 scenarios, item resampling is the only option, and it understates variance because items within a scenario are correlated. State this as a limitation, as the doc already does.
- **Fixing the bootstrap's undefined-resample problem.** With n₊ = 1, about (1 − 1/n)^n ≈ 37% of item resamples contain no positive. Skipping them conditions the CI on "positive present". Use a **stratified bootstrap** instead: resample positives and negatives separately, keeping n₊ and n₋ fixed. This is the standard approach for AUC CIs, so every resample is defined. With n₊ = 1, the positive is always the same item, so the CI reflects only uncertainty about the negatives. Say so in the report.
- **The exact permutation test for one positive.** With one positive and paired scorers A and B, the question reduces to "how many negatives does each scorer put above the positive?" A per-negative paired comparison (did A rank negative j below the positive while B did not?) is a McNemar-type 2×2 count on the negatives, and its exact binomial p-value is easy to explain.
- **Snippets:**
```python
import numpy as np
from scipy import stats
from sklearn.metrics import average_precision_score, roc_auc_score
from statsmodels.stats.contingency_tables import mcnemar
from statsmodels.stats.multitest import multipletests

def stratified_paired_boot(y, sa, sb, metric=average_precision_score, B=10000, seed=7):
    rng = np.random.default_rng(seed); y = np.asarray(y)
    pos, neg = np.where(y == 1)[0], np.where(y == 0)[0]
    d = np.empty(B)
    for b in range(B):
        idx = np.r_[rng.choice(pos, pos.size), rng.choice(neg, neg.size)]
        d[b] = metric(y[idx], sa[idx]) - metric(y[idx], sb[idx])
    return metric(y, sa) - metric(y, sb), np.percentile(d, [2.5, 97.5])

def paired_perm_test(y, sa, sb, metric=average_precision_score, n=10000, seed=7):
    # swap A/B scores per item (sign-flip of the pairing); scores must be on a comparable scale -> use ranks
    ra, rb = stats.rankdata(sa) / len(sa), stats.rankdata(sb) / len(sb)
    def stat(a, b): return metric(y, a) - metric(y, b)
    res = stats.permutation_test((ra, rb), stat, permutation_type="samples",
                                 n_resamples=n, alternative="two-sided", random_state=seed)
    return res.statistic, res.pvalue

def topk_mcnemar(y, sa, sb, k):
    ina = np.isin(np.arange(len(y)), np.argsort(-sa, kind="stable")[:k])
    inb = np.isin(np.arange(len(y)), np.argsort(-sb, kind="stable")[:k])
    pos = np.asarray(y) == 1
    b = np.sum(ina & ~inb & pos); c = np.sum(~ina & inb & pos)      # positives caught by one but not the other
    return mcnemar([[0, b], [c, 0]], exact=True).pvalue

# Holm across all comparisons L4 vs {L0..L3, EPSS, KEV, SSVC, WazuhVD, Wazuh, random}
# reject, p_adj, _, _ = multipletests(pvals, alpha=0.05, method="holm")
```
- **Families for correction.** Define two families up front: (i) the ladder increments L1−L0, L2−L1, L3−L2, L4−L3 (4 tests); (ii) L4 against the baselines (EPSS, KEV, SSVC, WazuhVD, Wazuh, random; 6 tests). Apply Holm within each family. Part B variants (B0–B5 against B4) form a third family. Pre-register these families in PLAN.md before looking at results.
- **DeLong caveat.** DeLong's asymptotic variance is unreliable with n₊ ≤ 5. Use it only once A1 has at least about 10 positives. Before that, use the stratified bootstrap or exact permutation.

### Gaps
- I did not find a study benchmarking DeLong against bootstrap at n₊ < 5. The caveat above is an inference from its asymptotic derivation.
- The Holm and Efron–Tibshirani references were cited from standard knowledge and not fetched in this session.

---

## Q3. Handling missing or unknown labels (`not_tried`), stratified designs and design-based estimators

### Takeaway
Treat the A1 sample as a **survey sample**. The project already draws stratified random pairs and records each one's inclusion probability π_i, so it can report **Horvitz–Thompson (HT) estimates** of frame-level quantities. Examples are "how many exploitable pairs exist in the frame" and "what share of them a scorer's top-k captures". These come with design-based CIs. `not_tried` is **non-response**, not a negative. Handle it with (a) bounds (all-0 vs all-1, Manski-style), (b) a response-propensity reweighting within strata, and (c) reporting the response rate per stratum. For the next labelling round, allocate the budget across **score strata** (for example top, middle and bottom tertile of EVS and of each baseline). Both high- and low-scored items then get labels, which lets you estimate recall and "missed positives".

### Cited Findings
- Fogliato et al. frame model evaluation under an annotation budget as a survey-sampling problem: stratification, sampling design and estimation. They compare HT estimation under simple random sampling with stratified designs (proportional and Neyman allocation) and model-assisted difference estimators. Stratifying on model predictions can sharply cut the annotations needed, though the gains vary across datasets. — [Fogliato et al., "A Framework for Efficient Model Evaluation…", ECCV 2024 / arXiv 2406.07320](https://arxiv.org/html/2406.07320v2)
- Stratified selection of test instances to label reduces the variance of risk estimates relative to random sampling. In some cases it cuts the samples needed for a 1% error estimate by about 60%. — [Kumar & Raj, "Classifier Risk Estimation under Limited Labeling Resources", arXiv 1607.02665](https://ar5iv.org/html/1607.02665)
- For precision estimation under limited samples, stratified sampling lowers variance when bins (for example score bins) are close to homogeneous in the true label. — [Amazon Science, "Estimating precisions for multiple binary classifiers under limited samples"](https://cdn.amazon.science/18/54/74b1b35f4f1dafc794d5a41aa6ca/estimating-precisions-for-multiple-binary-classifiers-under-limited-samples.pdf)
- F-score estimation from few labels with importance sampling. About 100 labels gave a variance of about 0.005 in reported settings. — [arXiv 2109.05720](https://arxiv.org/pdf/2109.05720)
- IR evaluation with incomplete judgments: infAP treats the judged set as a random sample of the pool and estimates AP as the expectation of a random experiment, so it is unbiased under uniform random judging. — [Yilmaz & Aslam CIKM 2006](https://www.khoury.northeastern.edu/home/jaa/papers/AslamYi06.pdf); [NIST infAP note](https://www-nlpir.nist.gov/projects/tv2006/infap/inferredAP.pdf)
- Arp et al. list **sampling bias** (data that does not reflect the real distribution) and **label inaccuracy** among 10 common pitfalls in security ML, found widely in 30 top-venue papers. — [Arp et al., USENIX Security 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/arp) ([arXiv 2010.09470](https://arxiv.org/abs/2010.09470))

### Inferences
- **HT estimator, using the π_i already in `pentest_candidates.csv`.** Let S be the labelled sample, y_i ∈ {0,1} exploited, and T_k(s) the top-k of scorer s over the *whole frame* (scores exist for all frame pairs; only labels are sampled).
  - Estimated total positives in the frame: N̂₊ = Σ_{i∈S} y_i / π_i
  - Estimated positives captured in the top-k: Ĉ_k(s) = Σ_{i∈S, i∈T_k(s)} y_i / π_i
  - Recall@k (coverage) ≈ Ĉ_k / N̂₊ (a ratio estimator). Precision@k (efficiency) ≈ Ĉ_k / k.
  - Variance: for stratified SRS without replacement, use the per-stratum variance with finite-population correction. Or bootstrap *within strata* (resample labelled rows within each stratum, recompute). Paired comparison between scorers is just the difference Ĉ_k(A) − Ĉ_k(B) computed on the same resamples.
  - This turns "6 labelled pairs" into an estimate about *the whole lab frame*. A reviewer will see this as the correct use of the stratified design that was already built.
- **`not_tried` as non-response.**
  1. Report the response rate (labelled / drawn) per stratum.
  2. **Bounds:** recompute every metric with all `not_tried` = 0 and with all = 1. If the sign of L4 − baseline holds at both extremes, the conclusion is robust to the missing labels (Manski-style partial identification; general idea, not a fetched source).
  3. **Reweighting:** within each stratum, inflate the weights of labelled rows by 1 / (response rate in the stratum), i.e. π_i' = π_i · r_h. This assumes labels are missing at random *within* strata. It is likely violated, because `not_tried` correlates with "no public exploit", which is itself a strong predictor of y = 0. State this.
  4. A distinct **third label**: `not_reachable` (feature not present or not called). This is arguably a true negative for *exploitability in this deployment*. Separate it from "time box ran out", which is truly unknown. Only the second should be treated as missing.
- **Next labelling round: stratify by score, not only by zone/CVSS.** To estimate *recall* (positives the EVS misses), low-EVS items must be labelled too. Recommended design: strata = EVS tertile × exploit-available, and Neyman-like allocation that oversamples the high tertile but keeps at least about 3 to 5 draws in every cell. Record π_i as today. If the budget allows, do the same with the strongest baseline (EPSS) so that items where EVS and EPSS *disagree* most are oversampled. Those discordant items are the only ones that carry information about A vs B (the McNemar logic). This is the "minimal test collections" idea in IR: judge the documents that most discriminate between systems. See Carterette, Allan & Sitaraman, SIGIR 2006, DOI 10.1145/1148170.1148219 (not fetched).
- **Pooling (IR).** An alternative or complement: label the union of the top-k of *every* scorer (L0–L4 and all baselines) plus a random sample of the rest. The pooled top-k set ensures every scorer's top-k is fully judged, so P@k is exact. The random remainder (with HT weights) gives recall.

### Gaps
- No source found on a vulnerability-specific labelling design. The stratified recipes come from general ML and IR evaluation.
- The Manski bounds and Carterette minimal test collections were cited from memory and not fetched.

---

## Q4. Power analysis, minimum sample sizes, and reporting when underpowered

### Takeaway
At the current n (6 labelled pairs, 1 positive; A3 with 2 positives), no paired test can reach conventional significance for any realistic effect. The defensible output is **effect sizes with CIs**, an explicit **"minimum detectable effect" (MDE)** statement, and a **simulation-based power curve** showing how many positives would be needed. Power is driven by the number of *positives* and *discordant items*, not by the total n.

### Cited Findings
- Card et al. show that underpowered comparisons are common in NLP. For example, on GLUE most comparisons with state-of-the-art models are underpowered, and a typical 2,000-sentence MT test set has only about 75% power to detect a 1 BLEU difference. Typical human-rating designs are too small to detect small differences. They recommend simulation-based power analysis and release notebooks. — [Card, Henderson, Khandelwal, Jia, Mahowald & Jurafsky, EMNLP 2020, arXiv 2010.06595](https://arxiv.org/pdf/2010.06595); [code: dallascard/NLP-power-analysis](https://www.github.com/dallascard/NLP-power-analysis)
- Sakai's topic-set-size design picks the number of topics needed for given (α, β, minimum detectable difference) from the paired t-test, ANOVA or CI-width formulas, using score variances from past data. He reports that IR topic sets are often smaller than these requirements, using Cohen's (α, β) = (0.05, 0.20). — [Sakai, "Topic set size design", Information Retrieval Journal 2016](https://link.springer.com/content/pdf/10.1007/s10791-015-9273-z.pdf); [Sakai 2018, *Laboratory Experiments in Information Retrieval: Sample Sizes, Effect Sizes, and Statistical Power*, Springer](https://www.springer.com/jp/book/9789811311987)
- Hanley & McNeil give closed-form approximations for the standard error of an AUC as a function of the AUC, n₊ and n₋. These are widely used for sample-size planning. One critique says the method can underestimate the minimum sample size. — [Hanley & McNeil 1982](https://math.ucdavis.edu/~saito/data/roc/hanley-mcneil-auc.pdf); [Stata `roctab` manual](https://www.stata.com/manuals/rroctab.pdf)
- Dietterich: McNemar's test is appropriate for single-run comparisons, and its power depends only on the discordant pairs. — [Dietterich 1998](https://web.engr.oregonstate.edu/~tgd/publications/dietterich-approximate-statistical-tests-nc1998.pdf)

### Inferences
- **Hanley–McNeil SE of one AUC (A = AUC):**
  Q₁ = A/(2−A), Q₂ = 2A²/(1+A),
  SE² = [A(1−A) + (n₊−1)(Q₁−A²) + (n₋−1)(Q₂−A²)] / (n₊ n₋).
  For example, with A = 0.8, n₊ = 2 and n₋ = 50, SE² ≈ [0.16 + 1·(0.667−0.64) + 49·(0.711−0.64)]/100 ≈ 0.037, so SE ≈ 0.19 and the 95% CI is about ±0.38. That is too wide to separate from 0.5 robustly (my arithmetic from the published formula). Even at n₊ = 5 the half-width is still about 0.25. A *difference* between two correlated AUCs needs fewer positives than a single AUC only when the scorers are highly correlated, which ladder steps are.
- **McNemar power for top-k.** Only discordant positives count (caught by A's top-k but not B's, or the reverse). With b vs c discordant, an exact two-sided binomial test at α = 0.05 needs b ≥ 6 with c = 0 to reject. So **at least 6 positives must fall in the disagreement set** before a top-k difference can be significant at all. This is a useful and concrete line for a professor.
- **"Rule of three"**: if 0 of n labelled low-score items are exploited, the 95% upper bound on the miss rate is about 3/n. For example, 0/20 gives ≤ 15%. Use Clopper–Pearson exact intervals (`statsmodels.stats.proportion.proportion_confint(method="beta")`) for every P@k and recall with small counts.
- **Simulation power recipe** (Card et al. style). (1) Take the *current* frame scores for L4 and the baseline. (2) Assume a generative label model, for example P(y=1 | item) = logistic(α + β·rank_percentile_L4), calibrated so that the expected number of positives in the frame matches the HT estimate N̂₊. (3) Simulate the labelling design (same strata, same π_i, same response rate). (4) Run the planned test (stratified bootstrap CI on ΔAP, or McNemar on top-k). (5) Repeat 1,000 times and record the rejection rate. (6) Sweep n_labelled and β. Report "with 40 labelled pairs and ~8 positives we have X% power to detect ΔAP = 0.2". This is the right reply to "is your experiment big enough?", and it reuses `eval_kg/sample.py`.
- **Reporting when underpowered** (this matches the direction already taken in `docs/evaluation.md`):
  - Lead with point estimate + 95% CI of the difference. Report p-values only as secondary, Holm-adjusted.
  - State the MDE, i.e. the smallest difference the current n could detect with 80% power (from the simulation).
  - Call results "consistent with" or "inconclusive", never "no effect". The current A1 result, ΔNDCG = +0.5 with CI [0, 0.61], is "directionally favourable, not significant, ceiling-limited".
  - Pool evidence across rungs qualitatively (A1, A2, A3, metamorphic, Part B) instead of resting on one test. An evidence ladder where each rung is weak but independent of the others is more convincing than one p-value. Be explicit about which rungs share labels or signals.
  - If several small independent tests point the same way, a sign-test or Fisher/Stouffer combination across *independent* rungs is possible. It is only valid if the rungs do not share items or labels (inference; not fetched).

### Gaps
- No published power tables were found specifically for AP or NDCG differences with fewer than 10 positives. Simulation is the only route.
- The Hanley–McNeil formula above was written from the published paper's standard form. The PDF was found but its full text was not read in this session, so verify the constants before quoting.

---

## Q5. Expert-judgement ground truth: pairwise comparison, best–worst scaling, inter-rater agreement

### Takeaway
When exploit labels are too scarce, add a **second, independent ground truth**: expert *relative* judgements of priority on a sample of (asset, CVE) pairs, collected with **best–worst scaling (BWS)** (4-tuples, scored best−worst) or **pairwise comparisons fitted with Bradley–Terry**. Measure agreement with **Krippendorff's α** (ordinal). This gives a graded, dense ranking label on 30 to 60 items with a few raters. It is a weaker kind of truth ("what experts would prioritise"), and raters must be blinded to the EVS and its inputs to avoid circularity.

### Cited Findings
- BWS: annotators see n-tuples (commonly n = 4) and pick the best and worst. Item score = (#best − #worst)/#appearances. About 1.5N to 2N 4-tuple annotations (N = number of items) give reliable scores. BWS gives more consistent annotations (split-half reliability) than rating scales, with fewer annotations. — [Kiritchenko & Mohammad, ACL 2017, "Best-Worst Scaling More Reliable than Rating Scales"](https://arxiv.org/pdf/1712.01765); [Mohammad BWS page and scripts](https://saifmohammad.com/WebPages/BestWorst.html); [Kiritchenko & Mohammad NAACL 2016](https://www.saifmohammad.com/WebDocs/BWS-naacl2016.pdf)
- BWS has been found more reliable than Likert ratings for summary-quality judgments across datasets. — [NAACL 2022 main.417](https://preview.aclanthology.org/fix_video/2022.naacl-main.417.pdf)
- BWS was developed by Louviere (1991), building on Luce and Marley's mathematical psychology. — [Mohammad BWS page](https://saifmohammad.com/WebPages/BestWorst.html)
- Krippendorff's α is proposed as a standard reliability measure that works for any number of coders, any level of measurement (nominal, ordinal, interval, ratio), any sample size, and missing data. Its CI comes from bootstrap. — [Hayes & Krippendorff 2007, Communication Methods and Measures 1(1):77–89](https://www.asc.upenn.edu/sites/default/files/2021-03/Answering%20the%20Call%20for%20a%20Standard%20Reliability%20Measure%20for%20Coding%20Data.pdf); [Krippendorff, bootstrapping α](https://asc.upenn.edu/sites/default/files/2021-03/Algorithm%20for%20Bootstrapping%20a%20Distribution%20of%20Alpha.pdf)
- Underpowered human evaluation designs are common, which argues for planning rater and item counts by simulation. — [Card et al. 2020](https://arxiv.org/pdf/2010.06595)
- Bradley–Terry: P(i beats j) = θ_i/(θ_i + θ_j). It is the standard model for pairwise preference data. — Bradley & Terry 1952, Biometrika 39(3/4):324–345, [JSTOR 2334029](https://www.jstor.org/stable/2334029) (standard reference, not fetched). Python implementation: [`choix`](https://github.com/lucasmaystre/choix) (not fetched).

### Inferences
- **Concrete design for this project:** 40 (asset, CVE) pairs drawn from the frame by EVS-tertile stratification. Each pair is shown as a CVE description + host role + zone + reachability facts *in plain words*, never the EVS, CVSS number or EPSS. 4-tuples, 2N = 80 tuples, split across 3 raters (for example the team plus one outside SOC analyst). That is about 30 to 60 minutes per rater. Score with best−worst counts, or fit Bradley–Terry on the pairwise preferences implied by each BWS answer (best > the other 3, the other 3 > worst).
- **Agreement:** report Krippendorff's α (ordinal) on split-half or per-rater scores, with a bootstrap CI. α ≥ 0.667 is Krippendorff's commonly cited minimum for tentative conclusions and 0.8 for firm ones (Krippendorff's guideline; not fetched this session). Cohen's κ only for 2 raters. Fleiss' κ for more than 2 raters with nominal labels.
- **Use as an evaluation rung:** Kendall τ-b between each scorer and the expert consensus, with a paired bootstrap over items for τ(L4) − τ(baseline). Also NDCG against the BT scores bucketed into grades.
- **Circularity risk:** experts given CR/IR/AR-type information ("this is the finance DB") are judging with the same signals L1 uses. That is fine *if framed* as "does the EVS reproduce expert prioritisation?" (construct validity). It is not independent evidence that context improves exploit prediction. Keep this rung clearly labelled as such.

### Gaps
- No source found on rater counts for security triage specifically. The 1.5N to 2N BWS rule comes from NLP sentiment annotation.
- Bradley–Terry and `choix` were not fetched. The Krippendorff α thresholds were cited from memory.

---

## Q6. Avoiding circularity and leakage

### Takeaway
Every label must be measurable *without* any signal the score consumes, or the evaluation must be **temporally split** so that the signal is frozen at T0 and the label arrives after T0. Where a signal is both a score input and a natural label (KEV, SSVC "active", alerts), run a **held-out-signal** variant: remove that input from the score and test against it as a label.

### Cited Findings
- Arp et al.'s pitfalls include **data snooping** (using information not available at deployment time, including temporal snooping where future data leaks into training or test), **spurious correlations** (artifacts that correlate with the label), **label inaccuracy**, and **inappropriate baselines**. Their recommendations include temporal splits, simple baselines, and reporting such limitations. — [Arp et al., USENIX Security 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/arp); [CACM 2024 version](https://mlsec.org/docs/2024-cacm.pdf)
- EPSS is itself evaluated by predicting *future* exploitation activity from features known at prediction time (a forward-in-time design). — [EPSS v3 arXiv 2302.14172](https://arxiv.org/abs/2302.14172); [EPSS 2019](https://arxiv.org/pdf/1908.04856)

### Inferences
- **Map each label to the score inputs it might leak into** (a leakage matrix for the paper):

  | Label | Inputs it could leak | Mitigation |
  |---|---|---|
  | A1 pentest exploited | E (via alert when exploiting), KEV/SSVC (team may pick known-exploited CVEs) | sampling is random (done). Compute L3 with E from data *before* the pentest session. Report A1 separately on non-KEV items |
  | A2 graded steps | E = H from the alert itself | for A2, compare L2-with-E-frozen-before-window. Otherwise L3/L4 trivially benefit |
  | A3 KEV after T0 | KEV at T0 (excluded), SSVC active (excluded) | already done. Also exclude EPSS after T0 (done) |
  | Part B measured reach | `lab/*.csv` topology that feeds CONNECTS_TO | measured live, not read (done). Note that the firewall config is a common cause of both |
  | Expert BWS | CR/IR/AR | label the rung as construct validity |

- **Held-out-signal test**: drop KEV from E (KEV is a score input), then test whether L4-without-KEV ranks KEV-listed pairs high. This is legitimate only if no other input is a deterministic function of KEV. SSVC "active" often is, so drop it too.
- **Freeze before label**: for every run, timestamp the CTI graph snapshot and assert that `max(input timestamp) < min(label timestamp)`. Add this as a unit test in `tests/test_eval_*.py`.
- **Authors as labellers.** The pentest team is the authors. Mitigate by (a) random sampling (done), (b) recording evidence files, and (c) if possible, having one external person verify a random 20% of the `yes`/`no` labels from the evidence. Report the agreement.

### Gaps
- I found no security-specific guidance on "authors as pentesters" bias beyond Arp et al.'s general label-quality pitfall.

---

## Q7. Ablation reporting: one-factor-at-a-time vs leave-one-out vs Shapley, weight robustness and rank stability

### Takeaway
The current ladder L0→L4 is a **cumulative, order-dependent** ablation, so the credit given to each component depends on the order of addition. With only 4 components (CR/IR/AR, MAV, E, P), it is cheap to evaluate **all 2⁴ = 16 subsets** and report (a) leave-one-out (L4 minus component), (b) add-one-to-L0, and (c) **exact Shapley contributions**, which average over all orders. Separately, run a **Monte Carlo perturbation** of the free parameters (β, γ, the CR/IR/AR mapping, the Table I MAV mapping, the k depth). Report the distribution of the metric and of rank stability (Kendall τ / RBO to the nominal ranking, top-k membership frequency), following the composite-indicator robustness tradition (Saltelli/Saisana).

### Cited Findings
- Global sensitivity analysis of composite indicators: most composite indicators show large gaps between nominal weights and the variables' effective importance (first-order Sobol main effects). Robustness analysis propagates all uncertain construction choices (weights, aggregation, normalisation) together and decomposes first-order vs total effects (interactions). — [Saltelli et al., *Global Sensitivity Analysis: The Primer*, Wiley 2008](https://hero.epa.gov/reference/1065450); [Paruolo, Saisana & Saltelli, "Ratings and rankings: voodoo or science?", JRSS-A 2013](https://ime.usp.br/~abe/lista/pdfIl1otfOjqV.pdf); [Huergo & Saisana useR! 2006 slides](https://user2006.r-project.org/Slides/Huergo+Saisana.pdf); [ISI 2011 "Weights as importance in composite indicators"](https://2011.isiproceedings.org/Abstracts/IPS079.01.html)
- Software for variance-based Sobol indices: R `sensobol`, Python SALib. — [sensobol vignette (J. Stat. Softw. 102(5))](https://www.jstatsoft.org/article/download/v102i05/4275)
- Shapley values give a unique additive attribution satisfying efficiency, symmetry, dummy and additivity. They are widely used for feature attribution (SHAP). — [Lundberg & Lee, NeurIPS 2017](https://papers.nips.cc/paper/7062-a-unified-approach-to-interpreting-model-predictions) (standard reference, not fetched)
- Demšar's critical-difference diagrams summarise many-variant comparisons over multiple datasets or units. — [Demšar 2006](https://www.jmlr.org/papers/v7/demsar06a.html)

### Inferences
- **Full-factorial ablation (16 configurations)**: for each subset S ⊆ {C (CR/IR/AR), M (MAV), E, P}, compute the score with the other components at their neutral value (C = M/M/M, MAV = base AV, E = X, P = 0), then the metric m(S). Then:
  - Shapley φ_j = Σ_{S ⊆ N\{j}} |S|!(n−|S|−1)!/n! · [m(S∪{j}) − m(S)]
  - Report φ_j with a bootstrap CI: resample items, recompute all 16 metrics, recompute φ.
  - Also report the **interaction** m({j,l}) − m({j}) − m({l}) + m(∅) for interesting pairs, for example E × P.
  The 16-row table is a compact, reviewer-friendly answer to "is the order of the ladder arbitrary?"
- **Weight and parameter perturbation (Monte Carlo)**: sample β, γ, CR/IR/AR multipliers and the MAV mapping from plausible ranges (uniform ±25%, or alternative published mappings), 1,000 draws. Report: (i) the distribution of ΔAP(L4 − best baseline); (ii) the share of draws where L4 beats the baseline; (iii) **rank stability**: median Kendall τ-b and RBO to the nominal ranking, and per-item frequency of being in the top-10. A first-order Sobol index per parameter (SALib `saltelli.sample` + `sobol.analyze`) shows which parameter choices the result depends on.
- **Part B ablation**: B0–B5 already form a one-factor-at-a-time design over edge type, zone rule, direction and depth. A 2×2×2 factorial (zone rule on/off × directed/undirected × k ∈ {1, 2}) would separate interactions. Report P/R/F1 per factor level with bootstrap CIs over (asset, CVE) pairs or over source assets. Assets are the better unit because pairs on the same asset are correlated.
- **Presentation:** one table per family with metric, Δ vs full model, 95% CI, and Holm-adjusted p. Plus one figure: a CD diagram or a forest plot of Δ with CIs.

### Gaps
- No source found on Shapley-based ablation for scoring formulas specifically. The recommendation carries the general Shapley axioms over.
- The Lundberg & Lee reference was not fetched.

---

## Q8. Metamorphic and property-based testing as a validation rung when labels are absent

### Takeaway
Metamorphic testing addresses the **oracle problem**: you cannot say what the "correct" EVS for an item is, but you can state **metamorphic relations (MRs)**, i.e. how the output must change when the input changes in a known way. A suite of MRs, run property-based (Hypothesis) over thousands of generated graphs and vectors, is a cheap, label-free rung. It shows the score and the blast-radius algorithm behave as their specification says (verification). It does not show they predict exploitation (validation), and the paper should state that distinction.

### Cited Findings
- Metamorphic testing addresses the oracle problem: instead of checking one output, it checks relations between outputs of related inputs. It is used both to generate test cases and to verify results. — [Chen, Kuo, Liu, Poon, Towey, Tse & Zhou, "Metamorphic Testing: A Review of Challenges and Opportunities", ACM Computing Surveys 51(1):4, 2018, DOI 10.1145/3143561](https://eprints.nottingham.ac.uk/51607/)
- A survey of 119 papers covers MT applications, empirical practice (including mutation-based evaluation of MR fault-detection effectiveness) and open challenges, since metamorphic relations were introduced in 1998. — [Segura, Fraser, Sánchez & Ruiz-Cortés, "A Survey on Metamorphic Testing", IEEE TSE 42(9):805–824, 2016](https://eprints.whiterose.ac.uk/110335/1/segura16-tse.pdf)

### Inferences
- **Candidate MRs for EVS (score_kg):**
  1. *Monotonicity in requirements*: raising CR, IR or AR of an asset (others fixed) never lowers L1–L4.
  2. *Monotonicity in exploit evidence*: changing E from X→U→P→F→H, or adding KEV, never lowers L3/L4.
  3. *Reachability*: adding an Internet path never lowers L2–L4. Removing it never raises them.
  4. *Propagation*: adding a CONNECTS_TO edge allowed by the zone policy never lowers P(u) or L4. Adding a high-criticality downstream host never lowers P(u).
  5. *Invariance*: renaming or relabelling hosts and permuting item order leave scores unchanged. Adding an isolated host (no edges) changes P(u) only through the normaliser len(crit) − 1 (make the expected direction explicit).
  6. *Bounds*: EVS ∈ [0, 10]. L4 = L3 when P = 0. With β = 0, L4 = L3.
- **Candidate MRs for the blast radius (Algorithm 1):**
  1. Adding a firewall deny never enlarges R(u). Adding an allow never shrinks it.
  2. *Depth monotonicity*: R_k(u) ⊆ R_{k+1}(u).
  3. *Duality*: v ∈ R_compromise(u) iff u ∈ R_disruption(v) under reversed edge direction (state it precisely from the impact-mode definition).
  4. B4 ⊆ B3 (directed ⊆ undirected) and B4 ⊆ B2 when CONNECTS_TO respects zones.
  5. Graph isomorphism invariance.
- **How to report it as a rung**: number of MRs, number of generated cases each (Hypothesis `@given` over random graphs and CVSS vectors), violations found and fixed. Optionally report **mutation score**: inject faults (flip a comparison, drop a direction check), then count how many mutants the MR suite kills. This is how Segura et al. describe judging MR effectiveness. Mutation score is the quantitative number a reviewer can check.

### Gaps
- No published MR catalogue exists for CVSS/EVS-type scores or for reachability algorithms. The MRs above were derived from the project's definitions and need checking against the paper's equations.
- Hypothesis and mutation tooling (for example `mutmut`) were not researched in this session.

---

## Cross-cutting recipe (summary for the report writer)

1. **Primary metrics (binary labels):** AP, the rank of each positive, effort-to-coverage / work saved over random, P@k and recall@k at operational k. All with Clopper–Pearson or stratified-bootstrap CIs, all next to a random-ranking baseline. NDCG for graded A2. RBO and τ-b for "does the step reorder?".
2. **Paired comparisons:** stratified paired bootstrap CI on Δmetric, a paired permutation test, McNemar on top-k discordant positives, and DeLong only once n₊ ≥ about 10. Holm within pre-declared families (ladder steps; L4 vs baselines; Part B variants).
3. **Partial labels:** HT-weighted estimates using the π_i already recorded. `not_tried` treated as non-response with all-0/all-1 bounds. The next round is stratified by score tertile and oversamples EVS-vs-EPSS disagreements.
4. **Power:** simulation-based power curve and MDE statement. McNemar needs at least 6 discordant positives to reject at α = 0.05. Report CIs, not "no effect".
5. **Independent truth:** expert BWS on about 40 items × 3 raters, Krippendorff's α, Kendall τ against the consensus. Labelled as construct validity.
6. **Leakage:** a leakage matrix, a freeze-before-label assertion, held-out-signal variants, the forward-in-time A3.
7. **Ablation:** a 16-subset factorial with Shapley contributions and interactions, and a Monte Carlo parameter perturbation with Sobol indices and rank-stability statistics.
8. **Metamorphic rung:** MR suite plus property-based generation plus mutation score.
