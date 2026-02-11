# When Agentic AI Meets Cybersecurity: A Systematic Literature Review

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/YOUR_USERNAME/agentic-ai-cybersecurity-slr/blob/main/notebooks/OWASP_Agentic_AI_SLR_Analysis.ipynb)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Studies](https://img.shields.io/badge/Studies_Reviewed-75-green.svg)](#dataset)

## Overview

This repository contains the **replication data, analysis scripts, and visualizations** for the systematic literature review paper:

> **"When Agentic AI Meets Cybersecurity: A Systematic Literature Review of Threats, Attacks, and Defences"**
>
> *Dr Rao Faizan Ali, University of Kent, 2026*

The study systematically reviews **75 peer-reviewed studies (2023–2026)** examining how agentic AI systems introduce new cybersecurity threats, with a focus on the **OWASP Agentic AI (ASI) Top 10** threat taxonomy.

---

## Repository Structure

```
agentic-ai-cybersecurity-slr/
│
├── README.md                          # This file
├── LICENSE                            # MIT License
│
├── data/
│   ├── appendix_a2_studies.csv        # All 75 included studies (Appendix A2)
│   ├── owasp_asi_scores.csv           # OWASP ASI Top 10 threat scores
│   ├── study_threat_mapping.csv       # Study-to-threat binary mapping
│   └── quality_assessment.csv         # Quality assessment scores (QA1-QA5)
│
├── notebooks/
│   └── OWASP_Agentic_AI_SLR_Analysis.ipynb  # Interactive Colab notebook
│
├── scripts/
│   └── generate_figures.py            # Standalone figure generation script
│
└── figures/
    ├── fig4_severity_likelihood.png   # Fig. 4: Severity vs. Likelihood
    ├── fig5_risk_matrix.png           # Fig. 5: Risk Matrix (Bubble Chart)
    └── ...                            # Additional analysis charts
```

---

## Dataset

### Appendix A2: 75 Included Studies

| Field | Description |
|-------|-------------|
| `ID` | Study identifier (S001–S075) |
| `Authors` | Author names |
| `Year` | Publication year (2023–2026) |
| `Title` | Full paper title |
| `Venue` | Publication venue |
| `Category` | Research type: ATK / SUR / DEF / THR / FRM |

**Category Definitions:**

| Code | Category | Count | Description |
|------|----------|-------|-------------|
| ATK | Attack Research | 23 (30.7%) | Studies demonstrating or evaluating attack techniques |
| SUR | Survey/Review | 18 (24.0%) | Literature synthesis and taxonomy papers |
| DEF | Defensive AI | 14 (18.7%) | Defense mechanisms and detection systems |
| THR | Threat Analysis | 11 (14.7%) | Threat modelling and risk assessment studies |
| FRM | Framework Design | 9 (12.0%) | Architectural frameworks and standards |

### OWASP ASI Top 10 Scores

Each threat category is scored across four dimensions derived from literature synthesis:

| Dimension | Scale | Description |
|-----------|-------|-------------|
| Severity | 1–10 | How damaging when exploited |
| Likelihood | 1–10 | How probable is exploitation |
| Attack Complexity | 1–10 | Technical sophistication required |
| Potential Impact | 1–10 | Maximum possible damage scope |

### Study-to-Threat Mapping

A binary mapping of which studies (S001–S075) provide evidence for each OWASP ASI threat category (ASI01–ASI10). Total mappings: **104** (studies can map to multiple threats).

---

## Key Figures

### Fig. 4: Severity vs. Likelihood Assessment

![Fig. 4](figures/fig4_severity_likelihood.png)

Grouped bar chart comparing severity and likelihood scores for each OWASP ASI threat category. Agent Goal Hijack (ASI01) and Identity & Privilege Abuse (ASI03) emerge as the highest-risk categories.

### Fig. 5: Risk Matrix

![Fig. 5](figures/fig5_risk_matrix.png)

Bubble chart mapping attack complexity against potential impact. Bubble size represents number of supporting studies. Threats in the upper-left quadrant (high impact, low complexity) represent the most critical priorities.

---

## Interactive Analysis

### Google Colab (Recommended)

Click the badge below to open the interactive notebook — no installation required:

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/YOUR_USERNAME/agentic-ai-cybersecurity-slr/blob/main/notebooks/OWASP_Agentic_AI_SLR_Analysis.ipynb)

The notebook includes:
- Complete dataset loading (all 75 studies)
- Original paper figures (Fig. 4 & Fig. 5)
- **10 additional chart types**: radar chart, heatmap, risk ranking, gap analysis, exploitability quadrant, category composition, correlation matrix, venue distribution, composite risk comparison, year × category analysis
- Summary statistics
- CSV export and download

### Local Execution

```bash
git clone https://github.com/YOUR_USERNAME/agentic-ai-cybersecurity-slr.git
cd agentic-ai-cybersecurity-slr
pip install pandas numpy matplotlib seaborn
python scripts/generate_figures.py
```

---

## Scoring Methodology

Threat scores were derived through **qualitative literature synthesis** of all 75 studies. Each study was mapped to relevant OWASP ASI categories based on its primary research contribution. Scores reflect:

- **Empirical evidence** from attack demonstrations (ATK studies)
- **Vulnerability scope** reported in survey papers (SUR studies)
- **Risk assessments** from threat analysis studies (THR studies)
- **Defense gap analysis** from defensive AI studies (DEF studies)
- **Framework recommendations** from standards bodies (FRM studies)

For detailed scoring rationale per threat category, see the `generate_figures.py` script documentation or the Colab notebook.

---

## Study Classification Criteria

Studies were classified into five categories using **deductive content analysis**:

1. **ATK**: Primary contribution is demonstrating or developing an attack technique
2. **DEF**: Primary contribution is a defense mechanism or detection system
3. **SUR**: Primary contribution is synthesizing existing literature
4. **THR**: Primary contribution is identifying or modelling threats
5. **FRM**: Primary contribution is an architectural framework or standard

Classification was performed independently by two reviewers (Cohen's κ = 0.87). See paper Section 2.1 for full methodology.

---

## Citation

If you use this dataset or analysis in your research, please cite:

```bibtex
@article{author2026agentic,
  title={When Agentic AI Meets Cybersecurity: A Systematic Literature Review of Threats, Attacks, and Defences},
  author={[Rao Faizan Ali]},
  journal={[Journal Name]},
  year={2026},
  note={Replication data: https://github.com/rfagreat/agentic-ai-cybersecurity-slr}
}
```

---

## License

This repository is licensed under the [MIT License](LICENSE). The datasets are provided for academic research purposes.

---

## Contact

- **Author**: Dr Rao Faizan Ali
- **Affiliation**: ICSS, University of Kent, Canterbury, Kent UK
- **Email**: r.f.ali@Kent.ac.uk

---

*Last updated: February 2026*
