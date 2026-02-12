# Software Testing at the Network Layer

**Automated HTTP API Quality Assessment and Security Analysis of Production Web Applications**

This repository contains the complete replication package for the paper:

> Mughal, A.H. (2026). *Software Testing at the Network Layer: Automated HTTP API Quality Assessment and Security Analysis of Production Web Applications*. arXiv preprint.

## Overview

We present an automated software testing framework that captures and analyzes HTTP traffic from production websites, detecting 8 classes of API call anti-patterns and producing composite quality scores (0-100). The framework also identifies security implications of the detected quality deficiencies, including supply-chain risks from third-party dependencies and cache poisoning vulnerabilities from missing cache headers.

**Key results from 18 production websites:**
- Quality scores range from 56.8 to 100.0 (mean 76.9)
- Redundant API calls and missing cache headers are the most pervasive anti-patterns
- Server-rendered sites consistently outperform JavaScript-heavy SPAs
- One site makes 2,684 requests per page load (447x more than the most minimal site)

## Repository Structure

```
.
├── capture.js              # HAR capture script (Node.js/Playwright)
├── analyze.py              # Analysis pipeline with 8 anti-pattern detectors
├── validate.py             # Independent data validation (8 automated checks)
├── data/
│   └── sites_anonymized.json   # Website corpus metadata (URLs redacted)
└── results/
    ├── site_scores.csv         # Quality scores for all 18 sites
    ├── anti_patterns.csv       # Per-capture anti-pattern data
    ├── summary_stats.csv       # Aggregate statistics
    └── per-site/               # Detailed JSON reports per site
        ├── news-1.json
        ├── commerce-1.json
        └── ... (18 files)
```

## Anonymization

All website identities are anonymized using category-based pseudonyms (e.g., News-1, Commerce-2, Travel-1) to protect the reputations of the tested organizations. Quality scores reflect a single measurement snapshot and should not be interpreted as definitive judgments on any organization's engineering quality.

## Reproducing the Analysis

### Prerequisites

- **Capture**: Node.js 18+, Playwright 1.49+
- **Analysis**: Python 3.10+, pandas, matplotlib, seaborn

### Step 1: Capture HAR files (for your own sites)

Create a `data/sites.json` file following the format in `data/sites_anonymized.json`, then:

```bash
npm install playwright
node capture.js --accessible-only
```

### Step 2: Analyze captured data

```bash
pip install pandas matplotlib seaborn
python analyze.py --anonymize
```

### Step 3: Validate results

```bash
python validate.py
```

## Anti-Pattern Detectors

| ID | Anti-Pattern | Weight | Description |
|----|-------------|--------|-------------|
| D1 | Redundant API Calls | 15% | Duplicate method+URL pairs within a page load |
| D2 | N+1 Query Patterns | 10% | Bursts of calls to parameterized URL patterns |
| D3 | Sequential Waterfalls | 10% | Same-domain calls that could be parallelized |
| D4 | Missing Cache Headers | 15% | No Cache-Control, ETag, or Last-Modified |
| D5 | Oversized Payloads | 15% | API responses > 100 KB |
| D6 | Missing Compression | 10% | Responses > 1 KB without Content-Encoding |
| D7 | Third-Party Overhead | 15% | Proportion of requests to external domains |
| D8 | Error Responses | 10% | HTTP 4xx/5xx status codes |

## Citation

If you use this framework or dataset in your research, please cite:

```bibtex
@misc{mughal2026softwaretestingnetworklayer,
      title={Software Testing at the Network Layer: Automated HTTP API Quality Assessment and Security Analysis of Production Web Applications}, 
      author={Ali Hassaan Mughal and Muhammad Bilal and Noor Fatima},
      year={2026},
      eprint={2602.08242},
      archivePrefix={arXiv},
      primaryClass={cs.SE},
      url={https://arxiv.org/abs/2602.08242}, 
}
```

## License

This project is released under the MIT License. See [LICENSE](LICENSE) for details.
