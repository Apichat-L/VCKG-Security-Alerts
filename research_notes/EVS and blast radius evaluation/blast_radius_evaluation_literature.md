# Evaluating blast-radius / impact-propagation / attack-graph reachability algorithms

Context used to tailor these notes (read from the repo, not modified): the blast radius here is
BR_k(a, c) = BFS on the asset reachability graph G_R (CONNECTS_TO edges permitted by the zone policy π), with
direction set by the CVE's impact mode (compromise = out-neighbours, disruption = in-neighbours), k = 1, plus a
propagation term P(u) over all reachable assets discounted by γ^d (`docs/scoring.md`). The lab is 17 Docker hosts in
5 zones (DMZ, APP, DATA, Office, MGMT) behind a zone-level firewall (`lab/assets.csv`, `lab/zone_edges.csv`). The
current plan already has Part A (score ladder L0→L4 against pentest labels, NDCG@10) and Part B (variants B0–B5 of
the blast radius, scored against three *measured* truth sets: network (TCP connect), usable (credential harvest +
harmless authenticated access), dependents (stop a host, run health checks)) (`docs/evaluation.md`,
`evaluation/README.md`). Items marked "[background knowledge]" are well-known publications I did not re-fetch in
this session; their bibliographic details should be double-checked before citation.

## 1. How attack-graph / impact algorithms are evaluated in the literature

### Takeaway
Most attack-graph papers evaluate **scalability (synthetic networks) plus one illustrative case study on a small
network**, not predictive accuracy. Predictive accuracy against what attackers actually achieved was tested
rarely, and the best-known test (Sommestad & Sandström 2015, MulVAL vs. a red-team exercise) found it poor. So a
small lab that measures real compromise/impact sets and scores the predicted sets against them is *above* the field's
usual evidential bar, not below it.

### Cited Findings
**Predictive-accuracy tests (the strongest and rarest kind)**
- Sommestad & Sandström, "An empirical test of the accuracy of an attack graph analysis tool," *Information & Computer Security* 23(5):516–531, 2015 (DOI 10.1108/ICS-06-2014-0036). They fed MulVAL with Nexpose scanner output and topology of 8 fictitious organisations (199 machines). Two attacker teams attacked for two days and the observed compromises were compared with the predictions. Accuracy was poor: hosts predicted *impossible* to compromise were >3× more likely to be compromised than hosts predicted possible, and 29% of "impossible" hosts were in fact compromised. The authors blame mainly the scanner's inaccuracy and how MulVAL interpreted vulnerability data. They also state that no prior work had tested attack-graph accuracy under realistic conditions. — [Crossref record/abstract](https://api.crossref.org/works/10.1108%2FICS-06-2014-0036); [BL catalogue](https://eld.bl.uk/catalog/100071075277_0x000001)
- A related thesis-level test (Sandström) compared MulVAL paths with the paths human attackers actually found. MulVAL proposed thousands of paths that no attacker tried, so path-level precision was very low. — [Sandström, "A test of attack graph-based evaluation of IT-security" (via search snippet; full text could not be fetched)](https://scispace.com/pdf/a-test-of-attack-graph-based-evaluation-of-it-security-mnzyqxk6cg.pdf)
- CySeMoL (Sommestad, Ekstedt, Holm) was validated at component level and then at system level by comparing its assessments with those of security professionals. Its assessments were judged comparable in reasonableness and correctness to a professional's (an expert-agreement design, not attack ground truth). — [CySeMoL paper](https://typeset.io/pdf/the-cyber-security-modeling-language-a-tool-for-assessing-2c6rppfc2r.pdf)
- 2025 agentic/LLM attack-graph construction with MulVAL on 54 web CTF tasks: ground truth is the CTF's annotated vulnerability set. Reported mean ground-truth vulnerability coverage was 53.7% (51.9% of tasks fully covered) and a mean "noise-path rate" of 83.9%. The authors say rule-level tests, expert validation and ablations are still needed. This is a recall-plus-noise design on tasks with known answers. — [arXiv 2609.15523](https://arxiv.org/html/2609.15523v1)
- The MDPI ML attack-graph generation paper reports path-detection accuracy of 89.52% (multi-output) and 80.68% (binary) against labels from an in-house dataset. — [Electronics 11(9):1332](https://www.mdpi.com/2079-9292/11/9/1332)

**Scalability and case-study evaluations (the common pattern)**
- MulVAL scalability: Ou, Boyer & McQueen, "A scalable approach to attack graph generation," CCS 2006, pp. 336–345. Logical attack graphs are generated in quadratic time, demonstrated on fully connected networks of 1000 machines on a Pentium 4 with 1 GB RAM. — [author PDF](https://www.cs.ksu.edu/~xou/publications/ccs06.pdf); [dblp](https://dblp.uni-trier.de/rec/conf/ccs/OuBM06.html). A secondary slide deck contrasts this with Sheyner's model-checking approach, where 10 hosts with 5 vulns each took 15 min and produced 10 M edges. — [slides](https://www.sambuz.com/doc/a-scalable-approach-to-attack-graph-generation-ppt-presentation-819111)
- NetSPA: Ingols, Lippmann & Piwowarski, "Practical attack graph generation for network defense," ACSAC 2006, pp. 121–130. Tested on an operational network of >250 hosts, where it "helped to discover a previously unknown configuration error", and on simulated networks of >50,000 hosts in <4 min. The companion MILCOM 2006 paper ("Validating and restoring defense in depth using attack graphs") reports field trials on up to 3,400 hosts. — [MIT LL page](https://www.ll.mit.edu/r-d/publications/practical-attack-graph-generation-network-defense); [MILCOM 2006](https://www.ll.mit.edu/r-d/publications/validating-and-restoring-defense-depth-using-attack-graphs). Note the evaluation style: "found a real misconfiguration" is a case-study validation.
- Bayesian attack graphs: Poolsappasit, Dewri & Ray, "Dynamic security risk management using Bayesian attack graphs," IEEE TDSC 9(1), 2012 (DOI 10.1109/TDSC.2011.34). Evaluated on a **test network of 8 hosts in two subnets with a tri-homed DMZ firewall**, about the size of this project's original lab, with >20 attack scenarios. The evaluation is a worked case study of static and dynamic risk. — [author PDF](https://cs.du.edu/~rdewri/data/MyPapers/Journals/2011TDSC.pdf); [IEEE Xplore](https://ieeexplore.ieee.org/abstract/document/5936075)
- Bayesian attack graph inference is checked against exact or reference answers on synthetic graphs of increasing size and evidence load (speed and accuracy). — [arXiv 2103.10212, "Stochastic simulation techniques for inference and sensitivity analysis of Bayesian attack graphs"](https://arxiv.org/pdf/2103.10212)
- k-zero-day safety: Wang, Jajodia, Singhal, Cheng & Noel, IEEE TDSC 2014 (earlier ESORICS 2010). The metric counts the distinct zero-day vulns needed to compromise an asset. Evaluation = formal definition + complexity analysis + heuristics for intractable cases + **case studies** on existing security practices. There is no empirical ground truth. — [NIST-hosted final version PDF](https://csrc.nist.gov/CSRC/media/Projects/Measuring-Security-Risk-in-Enterprise-Networks/documents/ieee_tdsc_2013_final_version.pdf); [NIST pub page](https://csrc.nist.gov/pubs/journal/2014/01/kzero-day-safety-network-security-metric-for-measu/final)
- Noel & Jajodia, "Metrics suite for network attack graph analytics" (CISR 2014; chapter in *Network Security Metrics*, Springer 2017). It defines families such as Topology (connectivity, cycles, depth of the attack graph) and Victimization (existence, exploitability, impact of vulns). These roll up to a 0–10 CVSS-like score, computed over Cauldron/CyGraph attack graphs. It is illustrated rather than validated against attacks. — [Springer chapter](https://rd.springer.com/chapter/10.1007/978-3-319-66505-4_7); [PDF](https://typeset.io/pdf/metrics-suite-for-network-attack-graph-analytics-19rw6rhglb.pdf)
- Idika & Bhargava, "Extending attack graph-based security metrics and aggregating their application," IEEE TDSC 9(1):75–85, 2012 (DOI 10.1109/TDSC.2010.61). They show that the Shortest Path, Number of Paths and Mean Path Length metrics can mislead individually (e.g., Number of Paths ignores attack effort), propose complementary metrics and an aggregation algorithm, and evaluate by **simulation**: how often the suite decides which of two attack graphs is more secure. — [Purdue PDF](https://www.cs.purdue.edu/homes/bb/nit/41_IEEE-TKDE-ExtendingAttackGraph.pdf); [researchr](https://researchr.org/publication/IdikaB12/bibtex). Idika's dissertation also studies how metric values respond to increasing vulnerabilities, a monotonicity-style behavioural analysis. — [Purdue dissertation](https://docs.lib.purdue.edu/dissertations/AAI3444572)
- Mission impact / dependency graphs: Jakobson's Impact Dependency Graphs (2011) propagate attack impact through AND/OR dependencies from assets to services to missions. Typical evaluation is a scenario walk-through. MITRE Crown Jewels Analysis supplies the dependency map (missions ↔ data flows ↔ cyber assets) used in SCRAM. Motzek (NATO STO) makes dependencies probabilistic. — [IEEE record](https://bvbvf1.bib-bvb.de/vufind/PrimoRecord/cdi_ieee_primary_5977648); [graph-models survey arXiv 2311.10050](https://arxiv.org/pdf/2311.10050); [Noel, NATO IST-148 2016](https://csis.gmu.edu/noel/pubs/2016_NATO_IST_148.pdf); [NATO STO MP-IST-148-04](https://www.sto.nato.int/publications/STO%20Meeting%20Proceedings/STO-MP-IST-148/MP-IST-148-04.pdf)
- Ransomware lateral-movement "Blast-Radius Estimate" BRE_K = expected % of assets compromised, from K-hop compromise probabilities (privilege-weighted adjacency-matrix exponentiation). It is evaluated on "anonymized enterprise snapshots" with no stated ground truth. Its evidence is qualitative: pruning high-weight edges gives the largest drop, which agrees with CISA/ATT&CK/NIST guidance. — [Tyagi & Murugesan, arXiv 2508.21005 (2025)](https://arxiv.org/abs/2508.21005)
- SCyTAG (Tayouri et al., 2025) builds attack graphs, then emulates the attack on a reduced cyber-twin. It is evaluated on one real and one fictitious organisational network by the reduction in components (up to 85%) while "preserving fidelity of the emulated attack". — [arXiv 2512.22669](https://arxiv.org/abs/2512.22669). A search snippet says it fills CALDERA ability variables from attack-graph entities (not confirmed in the abstract). — [HTML](https://arxiv.org/html/2512.22669)
- MAL Simulator (2026) explicitly states it does "not evaluate the predictive capability of the simulation model". Validating it would need comparing simulator observations with observations from a dataset. — [arXiv 2609.16563](https://arxiv.org/pdf/2609.16563)

**AD / cloud identity graphs (BloodHound-style, Wiz/Orca-style blast radius)**
- BloodHound's lineage comes from Dunagan et al. 2009 (edge blocking in AD attack graphs). Academic follow-ups evaluate *defence algorithms* (edge blocking) on real and synthetic AD graphs, measuring attacker success probability / path length, not prediction accuracy against red teams. — [arXiv 2212.04326, scalable edge blocking](https://arxiv.org/pdf/2212.04326); [arXiv 2310.10667](https://arxiv.org/pdf/2310.10667)
- Cloud IAM privilege-escalation "blast radius" tools are benchmarked against **catalogues of known escalation paths** (planted ground truth). One non-peer-reviewed benchmark tested 5 scanners against 57 AWS paths: cloud-audit 93%, Prowler 65%, Cloudsplaining 35%, PMapper 33%, CloudFox 7%. Its author discloses that 44% of the paths came from one tool's catalogue, which biases the result. — [haitmg.pl blog (2026)](https://haitmg.pl/blog/aws-iam-privesc-scanners-benchmark/). Datadog's pathfinding.cloud documents 65 AWS IAM escalation paths; 27 (42%) were detected by no evaluated OSS tool. Unit 42's IAM-Deescalate remediated 24/31 (77%) techniques in the intentionally vulnerable "IAM Vulnerable" environment. — [search snippets via Unit 42](https://unit42.paloaltonetworks.com/?p=124136)

**Surveys**
- Zeng et al., "Survey of attack graph analysis methods from the perspective of data and knowledge processing," *Security and Communication Networks* 2019, 2031063. It groups methods into graph-based, Bayesian, Markov, cost-optimisation and uncertainty methods, and covers practical usability and evaluation problems. — [Wiley](https://onlinelibrary.wiley.com/doi/10.1155/2019/2031063)
- Kaynar, "A taxonomy for attack graph generation and usage in network security," *J. Information Security and Applications* 29:27–56, 2016 (generation-focused) [background knowledge; cited as generation-focused by Zeng-adjacent sources] — [ScienceDirect DOI 10.1016/j.jisa.2016.02.001](https://doi.org/10.1016/j.jisa.2016.02.001)
- Lallie, Debattista & Bal, "A review of attack graph and attack tree visual syntax in cyber security," *Computer Science Review* 35:100219, 2020. It analysed >180 attack graphs/trees and found no standard representation. — [WRAP Warwick](https://wrap.warwick.ac.uk/131160); [dblp](https://dblp.uni-trier.de/rec/journals/csr/LallieDB20.html)
- Tayouri et al., "A survey of MulVAL extensions and their attack scenarios coverage" (arXiv 2208.05750, 2022). MulVAL is the most-used academic attack-graph generator. Coverage is evaluated by mapping interaction rules to ATT&CK techniques (a coverage metric, not accuracy). — [arXiv](https://arxiv.org/abs/2208.05750)
- "Attack graph analysis: an explanatory guide" (Computers & Security, 2023). — [ScienceDirect](https://www.sciencedirect.com/science/article/abs/pii/S0167404822004734)
- A 2024 ACM CSUR APT-detection review asks for more detail on graph creation, ground truth and standardised metrics, so ground truth is a recognised weakness across graph-based security work. — [ACM DOI 10.1145/3696014](https://dl.acm.org/doi/full/10.1145/3696014)

### Inferences
- Evidence types used in the field, from weakest to strongest: (i) illustrative example; (ii) scalability on synthetic graphs; (iii) case study on a small test network (Poolsappasit: 8 hosts); (iv) "it found a real misconfiguration" (NetSPA); (v) expert agreement (CySeMoL); (vi) planted-answer benchmarks (CTF tasks, IAM path catalogues); (vii) prediction vs. what attackers actually achieved (Sommestad & Sandström). This ordering maps naturally onto a "ladder" of evidence rungs.
- Sommestad & Sandström's main failure cause (scanner data and interpretation) applies directly to this project, whose CVE↔asset links come from CPE/Wazuh. That is a strong argument for keeping the blast-radius evaluation (network/dependency reachability) separate from the vulnerability-presence evaluation (Wazuh vs. pentest A1). The current repo design already does this.
- No source I found evaluates a **directional (compromise vs. disruption) blast radius** against measured dependency outages. The "dependents" truth set (stop a host, run health checks) looks like a novel, defensible contribution.

### Gaps
- I could not fetch the full text of Sommestad & Sandström 2015 or the Sandström thesis, so the exact metric (e.g., odds ratio, per-host confusion matrix) is unconfirmed beyond the abstract figures.
- I found no peer-reviewed evaluation of BloodHound path predictions against red-team outcomes, or of Wiz/Orca "blast radius" features. Vendor materials give no methodology.
- The Masaryk 2023 CNS "Lightweight impact assessment" paper (lateral movement and malware spread projection) came up in search but its PDF could not be read. — [link](https://is.muni.cz/publication/2313237/2023-CNS-Lightweight_Impact_Assessment-paper.pdf)

## 2. Ground-truth options (and their feasibility in a small lab)

### Takeaway
Feasible ground truths for a 17-host Docker lab are: (a) recorded manual pentest compromise sets; (b) automated
emulation runs (CALDERA / Atomic Red Team / Infection Monkey) that log which hosts were reached; (c) **measured**
reachability and dependency sets (TCP-connect matrix, credential usability, stop-and-health-check); and (d) synthetic
graphs and planted-answer configurations. Cyber-range exercises (Sommestad-style) and incident reconstructions are
the strongest, but they are mostly infeasible for a single university team.

### Cited Findings
- **Red-team exercise outcomes** are the gold standard used by Sommestad & Sandström: 2 attacker teams, 2 days, 199 hosts, per-host compromise observed. — [Crossref](https://api.crossref.org/works/10.1108%2FICS-06-2014-0036)
- **CALDERA** is MITRE's automated adversary-emulation platform. Its abilities map to ATT&CK techniques and chain into operations. It is used to drive multi-phase APT scenarios on testbeds such as SIMPLE-ICS. — [Miller et al., Black Hat EU 2017](https://www.blackhat.com/docs/eu-17/materials/eu-17-Miller-CALDERA-Automating-Adversary-Emulation.pdf); [SIMPLE-ICS arXiv 2602.22082](https://arxiv.org/pdf/2602.22082). MITRE CTID's **CALDERA Pathfinder** plugin scans a network, builds an attack-path graph, and turns paths into CALDERA adversaries for execution, which closes the predict→execute loop. — [CTID Pathfinder](https://ctid.mitre.org/projects/caldera-pathfinder/)
- An MIT thesis pairs an attack-path generator ("AttackPlanner") with CALDERA, which autonomously executed the generated plans. — [MIT record](https://libmast.utm.my/Record/mit-1721.1%2F139911/Description)
- COHORT couples CALDERA with a GNS3-emulated enterprise network and replays attacks after mitigations to check connectivity. It is a "re-run the attack after the change" design. — [arXiv 2606.30479](https://arxiv.org/pdf/2606.30479)
- PDDL-planner work argues that attack paths from attack-graph analysis should be **validated by executing them** (including exploits) against the real target network. — [arXiv 2206.06934 (layered reference model, RL + attack graphs)](https://arxiv.org/pdf/2206.06934) (from search summary)
- **Infection Monkey** (Guardicore/Akamai, open source BAS) propagates through a network and produces an "Infection Map" plus a security report with sections "Segmentation Issues" and "The Network from Infection Monkey's Eyes". It can run segmentation-only (no exploitation). Ideally every scanned node has edges only to the Island server, so any other edge is a segmentation break. — [Akamai docs: network segmentation](https://techdocs.akamai.com/infection-monkey/docs/network-segmentation); [security report](https://techdocs.akamai.com/infection-monkey/docs/security-report); [Black Hat 2016 whitepaper](https://www.blackhat.com/docs/us-16/materials/us-16-Ziv-Unleash-The-Infection_Monkey-A-Modern-Alternative-To-Pen-Tests-wp.pdf). It maps actions to ATT&CK (2020). — [Help Net Security](https://www.helpnetsecurity.com/2020/04/29/guardicore-infection-monkey/). I found no independent accuracy evaluation of Infection Monkey.
- **Planted-answer benchmarks**: CTF tasks with annotated vulns ([arXiv 2609.15523](https://arxiv.org/html/2609.15523v1)); IAM Vulnerable / pathfinding.cloud catalogues of known paths ([benchmark](https://haitmg.pl/blog/aws-iam-privesc-scanners-benchmark/)). The bias warning applies: a catalogue written by one tool's authors favours that tool.
- **Expert judgement** as ground truth (CySeMoL vs. professionals). — [CySeMoL](https://typeset.io/pdf/the-cyber-security-modeling-language-a-tool-for-assessing-2c6rppfc2r.pdf)
- **Synthetic graphs with reference answers** (Bayesian AG inference vs. exact inference). — [arXiv 2103.10212](https://arxiv.org/pdf/2103.10212)

### Inferences
- Feasibility for this lab (17 Docker hosts, 5 zones):
  | Ground truth | Feasible? | Notes / fit |
  |---|---|---|
  | Manual pentest compromise set per scenario (already S01–S13) | High | Part A rung (A1/A2 labels). For blast radius: the scenario's set of hosts *reached from* the foothold = observed compromise BR. Compare it with BR_k(foothold) |
  | CALDERA operation from each host as foothold (Sandcat agent + lateral-movement abilities) | Medium–High (Docker Linux hosts; needs SSH/creds abilities) | Repeatable, scriptable and timestamped, so it gives a per-foothold "achieved set". This is a Part A higher rung, or Part B truth set #4 ("emulated") |
  | Atomic Red Team T1021.x / T1570 tests | Medium | Technique-level checks of whether a lateral hop works. Fine-grained edge truth |
  | Infection Monkey (segmentation-only mode and exploit mode) | Medium (supports Linux; propagation uses SSH brute-force/known exploits) | Independent tool-generated reachability map, a third-party "network" truth set. It avoids the "our own nc script" circularity criticism |
  | Measured network / usable / dependents (repo already) | High | These are the Part B truth sets. Note "dependents" is the right truth for disruption mode |
  | Cyber-range exercise with external red team | Low | Could cite Sommestad as the reference design and state it as future work |
  | Incident reconstruction (public breach write-ups, e.g., replaying a known chain like Jenkins CVE-2024-23897 → DB) | Medium as a case study | Scenario walk-through rung, not statistics |
  | Synthetic topologies with analytic answers | High | Unit/property tests (Part B correctness rung) |
- Using an *independent* tool (Infection Monkey / CALDERA) for at least one truth set addresses the threat that the same team built both the predictor and the measurement scripts.

### Gaps
- I did not verify current CALDERA lateral-movement plugin capabilities (e.g., which abilities work in Linux containers without SSH keys). Check [CALDERA docs](https://caldera.readthedocs.io/) before planning.
- No public cyber-range dataset with per-host compromise labels suitable for blast-radius scoring was found in this session.

## 3. Metrics

### Takeaway
For set-valued predictions (blast radius = set of hosts), papers use per-host classification metrics
(precision/recall/F1, Jaccard, odds of compromise given predicted vs. not). For rankings (EVS, per-host BR size) they
use rank metrics (NDCG, Kendall τ/Spearman ρ). Path-level work reports coverage and "noise paths". Time-to-compromise
is a separate family (McQueen; MAL/securiCAD) that is rarely validated.

### Cited Findings
- **Odds/likelihood of compromise by predicted class**: Sommestad & Sandström report that hosts predicted impossible were >3× more likely to be compromised, and 29% of predicted-impossible hosts were compromised. This is effectively a false-negative rate on the negative class, plus a likelihood ratio. — [Crossref](https://api.crossref.org/works/10.1108%2FICS-06-2014-0036)
- **Coverage (recall) + noise-path rate (1 − path precision)**: 53.7% mean ground-truth coverage, 83.9% noise-path rate. — [arXiv 2609.15523](https://arxiv.org/html/2609.15523v1)
- **Detection rate over a catalogue** (recall over known paths): 7%–93% across IAM scanners. — [benchmark](https://haitmg.pl/blog/aws-iam-privesc-scanners-benchmark/)
- **Accuracy of path detection** (classification). — [MDPI 2022](https://www.mdpi.com/2079-9292/11/9/1332)
- **Graph-structure metrics as scores**: Shortest Path, Number of Paths, Mean Path Length, plus Idika & Bhargava's complementary suite. They are judged by whether they consistently order two networks. — [Idika & Bhargava](https://www.cs.purdue.edu/homes/bb/nit/41_IEEE-TKDE-ExtendingAttackGraph.pdf); topology/victimisation families — [Noel & Jajodia](https://rd.springer.com/chapter/10.1007/978-3-319-66505-4_7); k-zero-day count — [Wang et al.](https://csrc.nist.gov/CSRC/media/Projects/Measuring-Security-Risk-in-Enterprise-Networks/documents/ieee_tdsc_2013_final_version.pdf)
- **Blast radius as fraction of assets** (BRE_K = expected % of assets compromised) and LMS_K = mean pairwise lateral-movement probability. — [arXiv 2508.21005](https://arxiv.org/abs/2508.21005)
- **Time-to-compromise**: computed from NVD vulns via McQueen et al.'s model and used in securiCAD/MAL. This is a modelled quantity, not validated against observed times in the sources found. — [arXiv 2106.08568](https://arxiv.org/pdf/2106.08568); [KTH MAL project](https://www.kth.se/nse/research/software-systems-architecture-and-security/projects/mal-the-meta-attack-language-1.922174)
- **Cost / efficiency**: runtime vs. network size (MulVAL 1000 hosts; NetSPA 50,000 hosts <4 min); emulation-resource reduction (SCyTAG up to 85%). — [Ou et al.](https://www.cs.ksu.edu/~xou/publications/ccs06.pdf); [NetSPA](https://www.ll.mit.edu/r-d/publications/practical-attack-graph-generation-network-defense); [SCyTAG](https://arxiv.org/abs/2512.22669)
- **Remediation effectiveness**: % of techniques remediated (IAM-Deescalate 24/31); reduction in BRE/LMS after edge pruning; increase in attacker path length after edge blocking. — [Unit 42](https://unit42.paloaltonetworks.com/?p=124136); [arXiv 2508.21005](https://arxiv.org/abs/2508.21005); [arXiv 2212.04326](https://arxiv.org/pdf/2212.04326)

### Inferences
- Recommended metric set for this project:
  - **Set metrics per (foothold, mode)**: precision, recall, F1, Jaccard |P∩T|/|P∪T|. Report micro (pooled over all host pairs) *and* macro (mean over footholds). With 17 hosts, the 272 ordered host pairs give a 2×2 confusion table, and the odds ratio / likelihood ratio can be reported Sommestad-style ("a host outside BR is X× less likely to be reached").
  - **Rank metrics**: Spearman ρ / Kendall τ-b between per-host |BR| (or P(u)) and observed impact size (|achieved set| from emulation, or # dependents that failed). NDCG@k for the EVS ladder (already used).
  - **Path correctness**: for each pentest scenario, is the observed hop sequence a path in G_R? (path recall), and how many predicted k-hop paths were never used (noise rate, as in arXiv 2609.15523).
  - **Depth calibration (B5)**: recall@k and precision@k as k grows. The precision–recall curve over k justifies k = 1 vs. 2/3.
  - **Cost**: query latency and |BR|, already planned.
  - **Bootstrap CIs** over footholds/scenarios, given the small n (the repo already commits to reporting wide CIs).
- Time-to-compromise is not worth adopting as a ground-truth metric here (it is unvalidated in the literature, and manual pentest timings are noisy). Use it at most as a descriptive column from scenario YAML timestamps.

### Gaps
- No source found that uses rank correlation between per-host blast-radius size and observed impact specifically. The recommendation is my inference by analogy with ranking-metric practice.

## 4. Validation techniques when ground truth is scarce

### Takeaway
When ground truth is scarce, the literature relies on (i) synthetic graphs with analytically known or reference answers,
(ii) behavioural properties of metrics (how they respond as vulnerabilities and edges change), (iii) sensitivity
analysis, (iv) comparison with simple baselines and expert judgement, and (v) re-running attacks after a change.
Formal **metamorphic testing** of attack-graph metrics is essentially absent from the literature. That is a gap this
project can fill cheaply with property-based tests.

### Cited Findings
- Metamorphic testing addresses the "oracle problem" in security testing via relations between inputs and outputs. Examples: Mai et al. for web systems, and a 2025 catalogue of 8 system-agnostic metamorphic relations for online banking. — [arXiv 1912.05278](https://arxiv.org/pdf/1912.05278); [Rahman et al., CSR 2025](https://www.cs.montana.edu/izurieta/pubs/Rahman_CSR_2025.pdf). General review: Chen et al., "Metamorphic testing: a review of challenges and opportunities," ACM CSUR 51(1), 2018 [background knowledge] — [ACM](https://dl.acm.org/doi/10.1145/3143561)
- Monotonicity as a metamorphic relation (sweep one parameter, assert the metric moves one way within a tolerance) is used in ML testing tooling. — [FLTest docs](https://seed-vt.github.io/FLTest/metamorphic-testing/)
- Idika's dissertation studies how attack-graph metrics behave as network vulnerabilities increase. Idika & Bhargava show that single metrics can disagree or mislead, so properties must be checked explicitly. — [Purdue dissertation](https://docs.lib.purdue.edu/dissertations/AAI3444572); [TDSC paper](https://www.cs.purdue.edu/homes/bb/nit/41_IEEE-TKDE-ExtendingAttackGraph.pdf)
- k-zero-day safety is built so that more required zero-days means safer. Its formal properties are proven, not measured. — [Wang et al.](https://csrc.nist.gov/CSRC/media/Projects/Measuring-Security-Risk-in-Enterprise-Networks/documents/ieee_tdsc_2013_final_version.pdf)
- Sensitivity analysis of Bayesian attack graphs via stochastic simulation. — [arXiv 2103.10212](https://arxiv.org/pdf/2103.10212)
- Edge-pruning "what-if" experiments: removing high-weight edges should give the largest drop in blast radius. — [arXiv 2508.21005](https://arxiv.org/abs/2508.21005). Edge blocking that lengthens attacker paths. — [arXiv 2212.04326](https://arxiv.org/pdf/2212.04326)
- Re-run-after-change (COHORT replays CALDERA attacks after mitigations). — [arXiv 2606.30479](https://arxiv.org/pdf/2606.30479)
- Expert comparison (CySeMoL). — [CySeMoL](https://typeset.io/pdf/the-cyber-security-modeling-language-a-tool-for-assessing-2c6rppfc2r.pdf)

### Inferences
Concrete metamorphic / property relations for this blast radius (all cheap, offline, can be pytest/Hypothesis
tests on random graphs; they fit a **Part B "correctness" rung**):
- **MR1 Firewall monotonicity**: removing an ALLOWED_TO_REACH zone edge (tightening policy) ⇒ BR_k(a,c) ⊆ BR_k'(a,c) before, and P(u) does not increase.
- **MR2 Edge monotonicity**: adding a CONNECTS_TO edge ⇒ BR is a superset. Removing one ⇒ subset.
- **MR3 Depth monotonicity**: BR_k ⊆ BR_{k+1}. BR_∞ equals the BFS closure.
- **MR4 Vuln removal**: removing c from a's software leaves BR unaffected (BR is defined per (a, c)), but must remove (a, c) from the scored instance set. The EVS of other pairs must not change, except through E/MAV rules that are explicitly cross-pair.
- **MR5 Direction duality**: BR_disruption(a) on G equals BR_compromise(a) on the reversed graph Gᵀ.
- **MR6 Isolation**: a host with no permitted edges ⇒ BR = {a}, P = 0, EVS = Env.
- **MR7 Relabelling invariance**: renaming hosts or permuting the CSV row order leaves the outputs unchanged (graph isomorphism).
- **MR8 Criticality monotonicity**: raising CR/IR/AR of v ∈ R(u) does not decrease P(u). Changing it for v ∉ R(u) leaves P(u) unchanged.
- **MR9 Zone-merge**: merging two zones that already reach each other in both directions does not change BR.
- **MR10 Analytic synthetic cases**: on a chain of n hosts, |BR_k| = min(k, n−1−i)+1. On a star, compromise BR of the hub = all leaves at k = 1, and disruption BR of a leaf = {leaf, hub} only if the edge points leaf→hub. P(u) is closed-form for a chain with uniform crit (geometric series), so it can be checked to floating-point tolerance.
- **Sensitivity**: the repo already sweeps β, γ. Add k and edge-perturbation robustness: randomly drop or add 5–10% of CONNECTS_TO edges and report Kendall τ of the host ranking. This shows how much ranking stability depends on asset-inventory accuracy, which addresses Sommestad's "input data quality" failure mode.
- **Baselines** (these are Part B variants, scored against the same truth sets): degree / out-degree; betweenness centrality; PageRank; "reachable hosts ignoring vulns/zones" (B1); zone-level (B2); CVSS-only (L0, no propagation); |hosts in same subnet|. If B4 cannot beat out-degree on the dependents truth, that is an important finding to report honestly.

### Gaps
- I found no paper that explicitly applies metamorphic relations to attack-graph or blast-radius metrics (the search confirmed the absence rather than finding an example). The MR list above is a proposal, not something drawn from the literature.

## 5. How small-lab evaluations are presented convincingly, and mapping to Part A ladder / Part B variants

### Takeaway
Influential papers routinely evaluate on small networks (Poolsappasit et al.: 8 hosts; NetSPA's real-network check
found one misconfiguration). They convince through (1) a concrete scenario walk-through with numbers at every step,
(2) a precise threat-model and assumptions section, (3) scalability on synthetic graphs, and (4) honest
discussion of limitations. A small lab is persuasive when its truth is *measured independently* and the authors are
explicit that n is small (CIs, per-scenario tables), rather than claiming generality.

### Cited Findings
- 8-host, two-subnet, DMZ-firewall test network used as the full evaluation of a TDSC paper (Bayesian attack graphs; >20 attack scenarios). — [Poolsappasit et al.](https://cs.du.edu/~rdewri/data/MyPapers/Journals/2011TDSC.pdf)
- "Case studies" are the stated evaluation of k-zero-day safety in TDSC. — [Wang et al.](https://csrc.nist.gov/pubs/journal/2014/01/kzero-day-safety-network-security-metric-for-measu/final)
- An operational-network anecdote (finding an unknown config error), plus synthetic scale, made up NetSPA's ACSAC evaluation. — [MIT LL](https://www.ll.mit.edu/r-d/publications/practical-attack-graph-generation-network-defense)
- Mission-impact work (Jakobson IDG, Noel's NATO papers) is presented as scenario walk-throughs from attack point → asset capacity → dependent services → mission. — [arXiv 2311.10050](https://arxiv.org/pdf/2311.10050); [Noel NATO 2016](https://csis.gmu.edu/noel/pubs/2016_NATO_IST_148.pdf)
- A negative result from realistic testing (Sommestad) was itself publishable and is widely cited as the reason to validate. — [Crossref](https://api.crossref.org/works/10.1108%2FICS-06-2014-0036)
- Reviewers in adjacent areas want explicit description of ground truth and standardised metrics. — [ACM CSUR 10.1145/3696014](https://dl.acm.org/doi/full/10.1145/3696014)

### Inferences
**Proposed mapping of methods to the professor's structure** (rungs ordered by evidential strength; items already
in the repo marked ✓):

*Part A — evidence ladder for the blast radius (each rung is stronger evidence that BR predicts real impact):*
| Rung | Evidence | Literature precedent | Feasibility |
|---|---|---|---|
| A-R0 | Correctness: analytic synthetic graphs + metamorphic relations MR1–MR10 | Bayesian-AG reference answers (2103.10212); Idika behavioural analysis | Very high (offline tests) |
| A-R1 | Worked scenario walk-through (e.g., Jenkins CVE-2024-23897 compromise BR = {Jenkins, API}; API disruption BR = {API, Web, Jenkins}) with every intermediate value | Poolsappasit 8-host case study; k-zero-day case studies; Jakobson IDG | Very high (`score_kg explain` ✓) |
| A-R2 | Agreement with measured *network* reachability (TCP-connect matrix) ✓ | NetSPA "found a real config error"; Infection Monkey segmentation map | High |
| A-R3 | Agreement with measured *usable* reach (credentials) ✓ and *dependents* (stop-and-check) ✓, i.e. impact rather than mere reachability | Mission-impact dependency graphs (validated here by measurement, which IDG papers lacked) | High |
| A-R4 | Agreement with an *independent* emulation tool's achieved set (CALDERA operation per foothold; Infection Monkey exploit mode) | CALDERA Pathfinder; SCyTAG; COHORT | Medium |
| A-R5 | Agreement with human pentest compromise sets (S01–S13 hop sequences: path recall, BR recall from the foothold) ✓ partly | Sommestad & Sandström 2015 (red-team vs. MulVAL) | Medium (small n) |
| A-R6 | Downstream utility: L4 vs. L3 NDCG on A1 labels ✓; expert agreement (κ) | CySeMoL expert validation | Medium |

*Part B — variants/ablations (each scored on the A-R2–A-R5 truth sets with P/R/F1/Jaccard, plus cost):*
| Variant | Purpose | Literature analogue |
|---|---|---|
| B0 no BR (P = 0) ✓ | value of propagation at all | ablation |
| B1 unrestricted k-hop ✓ | "no rules" graph query | Sandström/2609.15523 noise-path problem: over-generation |
| B2 zone-level only ✓ | coarse subnet reachability | NetSPA-style reachability without host edges |
| B3 undirected ✓ | does impact-mode direction matter | (novel; no precedent found) |
| B4 proposed ✓ | Algorithm 1 | — |
| B5 k = 2, 3 ✓ | depth calibration (PR over k) | BRE_K / LMS_K K-hop (2508.21005) |
| B6 (add) centrality baselines: out-degree, betweenness, PageRank on G_R | is BR better than a generic graph heuristic? | Idika path-count metrics; centrality in AD hardening (ResearchGate fig. on snowball model) |
| B7 (add) CVSS-only / no-CTI / no-zone-policy / no-privilege-or-credential edges | per-signal ablation | Noel & Jajodia metric families |
| B8 (add) perturbed inventory (±5–10% edges) | robustness to bad asset data (Sommestad's failure cause) | Sommestad & Sandström |
| B9 (add) probabilistic BR (edge weights = exploit likelihood, e.g., EPSS) vs. deterministic | is the binary model enough? | Bayesian AG (Poolsappasit); BRE_K |

**Presentation tips derived from the sources:** one end-to-end figure for a single alert (graph → BR → P(u) → EVS);
a per-scenario table (foothold, predicted BR, achieved set, P/R); a confusion-matrix / odds-ratio statement à la
Sommestad; a scalability plot on synthetic graphs (e.g., 10–10,000 hosts) to pre-empt "only 17 hosts"; and a
threats-to-validity section naming same-team labels, lab-specific truth and small n (the repo already has this).

### Gaps
- I found no published "evidence ladder" framing in the attack-graph literature. The rung structure above is an inference that organises the precedents.
- I found no peer-reviewed source for Wiz/Orca-style cloud blast-radius validation methods, only vendor descriptions and blog benchmarks.
