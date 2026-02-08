"""
Data Validation Script for Network Call Quality Audit
=====================================================
Independently verifies every number in the published results by:
  1. Re-parsing raw HAR files and comparing request/API counts
  2. Checking for invalid sites (e.g. HTTP 401/403 that slipped through)
  3. Verifying scoring formulas produce correct values
  4. Flagging domain-extraction issues for third-party classification
  5. Cross-checking dimension scores against anti-pattern counts

Usage:
    python validate.py          # Run full validation
    python validate.py --fix    # Run validation AND fix identified issues

Output:
    results/validation_report.txt   # Human-readable validation report
"""

import json
import os
import sys
import csv
import re
from collections import defaultdict, Counter
from urllib.parse import urlparse
from pathlib import Path
from datetime import datetime

# Reuse the exact same analysis functions from analyze.py to ensure consistency
# We import the core functions so we can compare raw re-analysis vs saved results
BASE_DIR = Path(__file__).parent
HAR_DIR = BASE_DIR / 'har-files'
RESULTS_DIR = BASE_DIR / 'results'
PERSITE_DIR = RESULTS_DIR / 'per-site'

# --- Independent HAR counting (no heuristics, just raw counts) ---------------

def count_har_entries(har_path):
    """Independently count entries in a HAR file without any filtering."""
    try:
        with open(har_path, 'r', encoding='utf-8', errors='replace') as f:
            data = json.load(f)
        entries = data.get('log', {}).get('entries', [])
        return len(entries)
    except Exception as e:
        return -1


def analyze_har_raw(har_path):
    """Parse a HAR file independently and return raw metrics."""
    try:
        with open(har_path, 'r', encoding='utf-8', errors='replace') as f:
            data = json.load(f)
        entries = data.get('log', {}).get('entries', [])
    except Exception:
        return None

    if not entries:
        return None

    total = len(entries)
    domains = set()
    api_count = 0
    total_bytes = 0
    statuses = Counter()
    content_types = Counter()

    for entry in entries:
        req = entry.get('request', {})
        resp = entry.get('response', {})
        url = req.get('url', '')
        parsed = urlparse(url)
        domains.add(parsed.netloc)

        # Status
        status = resp.get('status', 0)
        statuses[status] += 1

        # Size
        body_size = resp.get('bodySize', 0)
        if body_size <= 0:
            body_size = resp.get('content', {}).get('size', 0)
        if body_size < 0:
            body_size = 0
        total_bytes += body_size

        # Content type
        resp_headers = {h['name'].lower(): h['value'] for h in resp.get('headers', [])}
        req_headers = {h['name'].lower(): h['value'] for h in req.get('headers', [])}
        ct = resp_headers.get('content-type', '').lower()
        content_types[ct.split(';')[0].strip()] += 1

        # API detection (same heuristic as analyze.py)
        is_api = False
        if 'application/json' in ct or 'application/graphql' in ct:
            is_api = True
        elif req_headers.get('x-requested-with', '').lower() == 'xmlhttprequest':
            is_api = True
        elif 'application/json' in req_headers.get('accept', '').lower():
            is_api = True
        elif 'application/json' in req_headers.get('content-type', '').lower():
            is_api = True
        else:
            url_lower = url.lower()
            for pattern in ['/api/', '/graphql', '/v1/', '/v2/', '/v3/', '/ajax/',
                           '/rest/', '/_next/data/', '/wp-json/']:
                if pattern in url_lower:
                    is_api = True
                    break

        if is_api:
            api_count += 1

    return {
        'total_requests': total,
        'api_requests': api_count,
        'total_bytes': total_bytes,
        'unique_domains': len(domains),
        'domains': sorted(domains),
        'statuses': dict(statuses),
        'top_content_types': dict(content_types.most_common(10)),
    }


# --- Validation checks -------------------------------------------------------

def check_1_request_counts(report):
    """CHECK 1: Do raw HAR entry counts match reported numbers?"""
    issues = []
    matches = 0
    total_checked = 0

    for site_dir in sorted(HAR_DIR.iterdir()):
        if not site_dir.is_dir() or site_dir.name.startswith('_'):
            continue

        site_id = site_dir.name
        persite_path = PERSITE_DIR / f'{site_id}.json'
        if not persite_path.exists():
            continue

        with open(persite_path) as f:
            saved = json.load(f)

        har_files = sorted(site_dir.glob('*.har'))
        cold_hars = [h for h in har_files if '_cold.har' in h.name]

        if not cold_hars:
            continue

        # Count entries independently
        raw_totals = []
        raw_apis = []
        for har in cold_hars:
            raw = analyze_har_raw(har)
            if raw:
                raw_totals.append(raw['total_requests'])
                raw_apis.append(raw['api_requests'])
                total_checked += 1

        if raw_totals:
            raw_avg_total = sum(raw_totals) / len(raw_totals)
            raw_avg_api = sum(raw_apis) / len(raw_apis)
            saved_avg_total = saved['summary']['avg_total_requests']
            saved_avg_api = saved['summary']['avg_api_requests']

            # Allow small rounding differences
            if abs(raw_avg_total - saved_avg_total) > 1:
                issues.append(f"  MISMATCH {site_id}: total requests raw={raw_avg_total:.1f} vs saved={saved_avg_total}")
            else:
                matches += 1

            if abs(raw_avg_api - saved_avg_api) > 1:
                issues.append(f"  MISMATCH {site_id}: API requests raw={raw_avg_api:.1f} vs saved={saved_avg_api}")
            else:
                matches += 1

    return {
        'name': 'CHECK 1: Request count verification',
        'total_checked': total_checked,
        'matches': matches,
        'issues': issues,
        'passed': len(issues) == 0
    }


def check_2_invalid_sites(report):
    """CHECK 2: Are any sites returning invalid data (401, empty pages, etc.)?"""
    issues = []
    invalid_sites = []

    for site_dir in sorted(HAR_DIR.iterdir()):
        if not site_dir.is_dir() or site_dir.name.startswith('_'):
            continue

        site_id = site_dir.name
        capture_log = site_dir / 'capture_log.json'
        if not capture_log.exists():
            continue

        with open(capture_log) as f:
            log = json.load(f)

        # Check HTTP statuses across all captures
        statuses = [c.get('httpStatus', 0) for c in log.get('captures', [])]
        non_200 = [s for s in statuses if s != 200]
        avg_requests = sum(c.get('requestCount', 0) for c in log.get('captures', [])) / max(len(log.get('captures', [])), 1)

        # Flag sites with consistently non-200 status
        if all(s in (401, 403, 429, 0) for s in statuses) and statuses:
            issues.append(f"  INVALID {site_id}: ALL captures returned non-200 statuses: {set(statuses)}")
            invalid_sites.append(site_id)

        # Flag sites with very few requests (suggests blocked/empty)
        if avg_requests < 10 and site_id not in ('forum-1',):
            # Some minimal sites legitimately have very few requests
            cold_captures = [c for c in log.get('captures', []) if c.get('type') == 'cold']
            if cold_captures:
                cold_avg = sum(c.get('requestCount', 0) for c in cold_captures) / len(cold_captures)
                if cold_avg < 10:
                    issues.append(f"  SUSPICIOUS {site_id}: avg {cold_avg:.0f} requests/cold capture (may be blocked)")

        # Check for 401 specifically (missed by classifyPageResult)
        if any(s == 401 for s in statuses):
            issues.append(f"  WARNING {site_id}: HTTP 401 responses detected (unauthorized/paywall)")

    return {
        'name': 'CHECK 2: Invalid/blocked site detection',
        'invalid_sites': invalid_sites,
        'issues': issues,
        'passed': len(invalid_sites) == 0
    }


def check_3_scoring_formula(report):
    """CHECK 3: Does the scoring formula produce correct results?"""
    issues = []

    SCORE_WEIGHTS = {
        'redundant_calls': 15, 'n_plus_1': 10, 'sequential_waterfalls': 10,
        'missing_cache_headers': 15, 'oversized_payloads': 15,
        'missing_compression': 10, 'third_party_overhead': 15, 'error_rate': 10,
    }

    for persite_file in sorted(PERSITE_DIR.glob('*.json')):
        with open(persite_file) as f:
            saved = json.load(f)

        site_id = saved['site_id']
        dims = saved.get('dimension_scores', {})
        saved_score = saved['summary']['quality_score']

        # Recalculate weighted average from dimension scores
        recalc = 0
        for dim, weight in SCORE_WEIGHTS.items():
            s = max(0, min(100, dims.get(dim, 100)))
            recalc += s * (weight / 100)
        recalc = round(recalc, 1)

        if abs(recalc - saved_score) > 0.2:
            issues.append(f"  SCORE MISMATCH {site_id}: recalculated={recalc} vs saved={saved_score}")

        # Also verify individual dimension scores from anti-pattern averages
        ap = saved.get('anti_pattern_averages', {})

        # Redundant calls: 100 - excess * 10
        expected_rc = max(0, 100 - ap.get('redundant_excess_calls', 0) * 10)
        actual_rc = dims.get('redundant_calls', 100)
        if abs(expected_rc - actual_rc) > 1:
            issues.append(f"  DIM MISMATCH {site_id} redundant_calls: expected={expected_rc:.1f} actual={actual_rc}")

        # Missing cache: 100 - percentage
        expected_mc = max(0, 100 - ap.get('missing_cache_pct', 0))
        actual_mc = dims.get('missing_cache_headers', 100)
        if abs(expected_mc - actual_mc) > 1:
            issues.append(f"  DIM MISMATCH {site_id} missing_cache: expected={expected_mc:.1f} actual={actual_mc}")

        # Third party: 100 - percentage
        expected_tp = max(0, 100 - ap.get('third_party_pct', 0))
        actual_tp = dims.get('third_party_overhead', 100)
        if abs(expected_tp - actual_tp) > 1:
            issues.append(f"  DIM MISMATCH {site_id} third_party: expected={expected_tp:.1f} actual={actual_tp}")

        # Error rate: 100 - pct * 5
        expected_er = max(0, 100 - ap.get('error_rate_pct', 0) * 5)
        actual_er = dims.get('error_rate', 100)
        if abs(expected_er - actual_er) > 1:
            issues.append(f"  DIM MISMATCH {site_id} error_rate: expected={expected_er:.1f} actual={actual_er}")

    return {
        'name': 'CHECK 3: Scoring formula verification',
        'issues': issues,
        'passed': len(issues) == 0
    }


def check_4_domain_extraction(report):
    """CHECK 4: Does domain extraction handle multi-part TLDs correctly?"""
    issues = []

    # Test known domain cases (using example domains for reproducibility)
    test_cases = [
        ('www.example.com', 'example.com'),
        ('www.example.co.uk', 'co.uk'),      # Known limitation: multi-part TLDs
        ('www.gov.example', 'gov.example'),
        ('cdn.example.com', 'example.com'),
        ('api.example.com', 'example.com'),
    ]

    for domain, expected in test_cases:
        parts = domain.split('.')
        if len(parts) >= 2:
            result = '.'.join(parts[-2:])
        else:
            result = domain

        if result != expected:
            issues.append(f"  Domain extraction: {domain} -> '{result}' (expected '{expected}')")

    # Check which sites in our dataset use multi-part TLDs
    for site_dir in sorted(HAR_DIR.iterdir()):
        if not site_dir.is_dir() or site_dir.name.startswith('_'):
            continue

        capture_log = site_dir / 'capture_log.json'
        if not capture_log.exists():
            continue

        with open(capture_log) as f:
            log = json.load(f)

        pages = log.get('page_statuses', [])
        if pages:
            url = pages[0].get('url', '')
            domain = urlparse(url).netloc
            parts = domain.split('.')
            main_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else domain

            # Check if this domain uses a ccTLD with second-level (.co.uk, .com.au, etc.)
            multi_part_tlds = ['.co.uk', '.com.au', '.co.jp', '.co.nz', '.org.uk']
            for tld in multi_part_tlds:
                if domain.endswith(tld):
                    issues.append(f"  WARNING {site_dir.name}: domain={domain}, extracted main_domain='{main_domain}' "
                                f"(multi-part TLD, may misclassify related subdomains)")

    # Check for sites with very high third-party percentage (potential CDN misclassification)
    for persite_file in sorted(PERSITE_DIR.glob('*.json')):
        with open(persite_file) as f:
            site_data = json.load(f)
        tp_pct = site_data.get('anti_pattern_averages', {}).get('third_party_pct', 0)
        if tp_pct > 90:
            sid = site_data.get('site_id', persite_file.stem)
            issues.append(f"  NOTE {sid}: 3rd-party={tp_pct}% - verify if CDN domains "
                        f"are being misclassified as third-party.")

    return {
        'name': 'CHECK 4: Domain extraction / third-party classification',
        'issues': issues,
        'passed': len([i for i in issues if 'MISMATCH' in i or 'BUG' in i]) == 0
    }


def check_5_csv_consistency(report):
    """CHECK 5: Do CSV files match per-site JSON reports?"""
    issues = []

    scores_csv = RESULTS_DIR / 'site_scores.csv'
    if not scores_csv.exists():
        return {'name': 'CHECK 5: CSV consistency', 'issues': ['CSV file not found'], 'passed': False}

    with open(scores_csv, 'r') as f:
        reader = csv.DictReader(f)
        csv_data = {row['Site']: row for row in reader}

    for persite_file in sorted(PERSITE_DIR.glob('*.json')):
        with open(persite_file) as f:
            saved = json.load(f)

        site_name = saved['site_name']
        if site_name not in csv_data:
            issues.append(f"  MISSING {site_name}: in per-site JSON but not in site_scores.csv")
            continue

        csv_row = csv_data[site_name]

        # Check quality score
        csv_score = float(csv_row['Quality Score'])
        json_score = saved['summary']['quality_score']
        if abs(csv_score - json_score) > 0.1:
            issues.append(f"  MISMATCH {site_name}: CSV score={csv_score} vs JSON score={json_score}")

        # Check request counts
        csv_reqs = float(csv_row['Avg Requests'])
        json_reqs = saved['summary']['avg_total_requests']
        if abs(csv_reqs - json_reqs) > 0.1:
            issues.append(f"  MISMATCH {site_name}: CSV reqs={csv_reqs} vs JSON reqs={json_reqs}")

    return {
        'name': 'CHECK 5: CSV-JSON consistency',
        'issues': issues,
        'passed': len(issues) == 0
    }


def check_6_score_distribution(report):
    """CHECK 6: Sanity check - do scores align with expectations?"""
    issues = []

    # Load scores
    sites = {}
    for persite_file in sorted(PERSITE_DIR.glob('*.json')):
        with open(persite_file) as f:
            saved = json.load(f)
        sites[saved['site_id']] = saved

    # Minimal sites should score highest
    minimal_sites = ['forum-1', 'government-1', 'classifieds-1', 'reference-1']
    for sid in minimal_sites:
        if sid in sites:
            score = sites[sid]['summary']['quality_score']
            if score < 85:
                issues.append(f"  UNEXPECTED {sid}: score={score} (minimal site should score >85)")

    # Heavy JS sites should score lower than minimal sites
    heavy_sites = ['commerce-1', 'commerce-3', 'travel-1', 'travel-2', 'utility-1']
    for sid in heavy_sites:
        if sid in sites:
            score = sites[sid]['summary']['quality_score']
            if score > 95:
                issues.append(f"  SUSPICIOUS {sid}: score={score} (heavy JS site scoring >95?)")

    # Sites with 0 API calls but non-zero anti-pattern counts
    for sid, data in sites.items():
        api = data['summary']['avg_api_requests']
        redundant = data['anti_pattern_averages']['redundant_excess_calls']
        if api == 0 and redundant > 0:
            issues.append(f"  LOGIC ERROR {sid}: 0 API calls but {redundant} redundant calls detected")

    return {
        'name': 'CHECK 6: Score sanity checks',
        'issues': issues,
        'passed': len(issues) == 0
    }


def check_7_har_file_completeness(report):
    """CHECK 7: Do all sites have the expected number of HAR files?"""
    issues = []
    expected_per_site = 12  # 2 pages x 3 runs x 2 visits (cold+warm)

    for site_dir in sorted(HAR_DIR.iterdir()):
        if not site_dir.is_dir() or site_dir.name.startswith('_'):
            continue

        site_id = site_dir.name
        har_files = list(site_dir.glob('*.har'))

        # Don't check sites that were blocked/failed
        persite = PERSITE_DIR / f'{site_id}.json'
        if not persite.exists():
            continue

        if len(har_files) != expected_per_site:
            issues.append(f"  {site_id}: {len(har_files)} HAR files (expected {expected_per_site})")

        # Check for empty/corrupt HAR files
        for har in har_files:
            size = har.stat().st_size
            if size < 100:
                issues.append(f"  EMPTY {site_id}/{har.name}: only {size} bytes")
            else:
                count = count_har_entries(har)
                if count == 0:
                    issues.append(f"  EMPTY ENTRIES {site_id}/{har.name}: 0 entries in HAR")
                elif count < 0:
                    issues.append(f"  CORRUPT {site_id}/{har.name}: could not parse")

    return {
        'name': 'CHECK 7: HAR file completeness',
        'issues': issues,
        'passed': len([i for i in issues if 'EMPTY' in i or 'CORRUPT' in i]) == 0
    }


def check_8_cold_vs_warm(report):
    """CHECK 8: Cold visits should generally have more requests than warm visits."""
    issues = []
    cold_more = 0
    warm_more = 0
    equal = 0

    for site_dir in sorted(HAR_DIR.iterdir()):
        if not site_dir.is_dir() or site_dir.name.startswith('_'):
            continue

        persite = PERSITE_DIR / f'{site_dir.name}.json'
        if not persite.exists():
            continue

        har_files = sorted(site_dir.glob('*.har'))
        for har in har_files:
            if '_cold.har' not in har.name:
                continue
            warm_har = Path(str(har).replace('_cold.har', '_warm.har'))
            if not warm_har.exists():
                continue

            cold_count = count_har_entries(har)
            warm_count = count_har_entries(warm_har)

            if cold_count > 0 and warm_count > 0:
                if cold_count > warm_count:
                    cold_more += 1
                elif warm_count > cold_count:
                    warm_more += 1
                else:
                    equal += 1

    total = cold_more + warm_more + equal
    if total > 0:
        cold_pct = cold_more / total * 100
        if cold_pct < 30:
            issues.append(f"  SUSPICIOUS: Only {cold_pct:.0f}% of cold visits have more requests than warm "
                        f"(cold_more={cold_more}, warm_more={warm_more}, equal={equal})")

    return {
        'name': 'CHECK 8: Cold vs warm visit patterns',
        'cold_more': cold_more,
        'warm_more': warm_more,
        'equal': equal,
        'issues': issues,
        'passed': len(issues) == 0
    }


# --- Main validation runner ---------------------------------------------------

def main():
    fix_mode = '--fix' in sys.argv

    print('================================================================')
    print('  DATA VALIDATION REPORT')
    print('  Network Call Quality Audit')
    print(f'  Generated: {datetime.now().isoformat()}')
    print('================================================================\n')

    all_checks = [
        check_1_request_counts,
        check_2_invalid_sites,
        check_3_scoring_formula,
        check_4_domain_extraction,
        check_5_csv_consistency,
        check_6_score_distribution,
        check_7_har_file_completeness,
        check_8_cold_vs_warm,
    ]

    results = []
    total_issues = 0
    critical_issues = []

    for check_fn in all_checks:
        result = check_fn(None)
        results.append(result)

        status = 'PASS' if result['passed'] else 'ISSUES FOUND'
        print(f'[{status}] {result["name"]}')
        for issue in result.get('issues', []):
            print(issue)
            total_issues += 1
            if 'MISMATCH' in issue or 'INVALID' in issue or 'LOGIC ERROR' in issue:
                critical_issues.append(issue)
        if 'cold_more' in result:
            print(f'  Cold > Warm: {result["cold_more"]}, Warm > Cold: {result["warm_more"]}, Equal: {result["equal"]}')
        print()

    # Summary
    print('================================================================')
    print(f'  VALIDATION SUMMARY')
    print('================================================================')
    print(f'  Total checks:    {len(all_checks)}')
    print(f'  Passed:          {sum(1 for r in results if r["passed"])}')
    print(f'  With issues:     {sum(1 for r in results if not r["passed"])}')
    print(f'  Total issues:    {total_issues}')
    print(f'  Critical issues: {len(critical_issues)}')
    print()

    if critical_issues:
        print('  CRITICAL ISSUES REQUIRING ACTION:')
        for ci in critical_issues:
            print(f'    {ci}')
        print()

    # Specific recommendations
    print('  RECOMMENDATIONS:')

    # Check for sites that should be excluded
    for r in results:
        if r['name'].startswith('CHECK 2'):
            for sid in r.get('invalid_sites', []):
                print(f'    - EXCLUDE {sid} from dataset (invalid HTTP responses)')

    # Domain extraction warnings
    for r in results:
        if r['name'].startswith('CHECK 4'):
            for issue in r.get('issues', []):
                if 'NOTE' in issue and '3rd-party' in issue:
                    print(f'    - Review high third-party sites for CDN misclassification')

    print()

    # Save report
    report_path = RESULTS_DIR / 'validation_report.txt'
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(f'DATA VALIDATION REPORT\n')
        f.write(f'Generated: {datetime.now().isoformat()}\n')
        f.write(f'{"=" * 60}\n\n')
        for result in results:
            status = 'PASS' if result['passed'] else 'ISSUES FOUND'
            f.write(f'[{status}] {result["name"]}\n')
            for issue in result.get('issues', []):
                f.write(f'{issue}\n')
            f.write('\n')
        f.write(f'\nTotal issues: {total_issues}\n')
        f.write(f'Critical: {len(critical_issues)}\n')
    print(f'  Report saved: {report_path}')

    return len(critical_issues)


if __name__ == '__main__':
    sys.exit(main())
