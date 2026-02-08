"""
Network Call Quality Audit -- HAR Analysis Pipeline
===================================================
Single-file script that:
  1. Parses all HAR files from har-files/
  2. Detects 8 anti-patterns per capture
  3. Scores each site on a 0-100 quality rubric
  4. Generates paper-ready CSV tables and matplotlib figures

Usage:
    python analyze.py                # Analyze all captured sites
    python analyze.py --site mysite  # Analyze one site
    python analyze.py --figures-only # Regenerate figures from existing results

Output:
    results/anti_patterns.csv        # Every detected anti-pattern (one row per finding)
    results/site_scores.csv          # Quality scores per site (paper Table 1)
    results/summary_stats.csv        # Aggregate statistics (paper Table 2)
    results/per-site/<id>.json       # Detailed per-site JSON report
    paper/figures/*.png              # Paper-ready visualizations
"""

import json
import os
import sys
import csv
import re
from collections import defaultdict, Counter
from urllib.parse import urlparse, parse_qs
from pathlib import Path
from datetime import datetime

import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend for saving figures
import matplotlib.pyplot as plt
import seaborn as sns

# --- Configuration ------------------------------------------------------------

BASE_DIR = Path(__file__).parent
HAR_DIR = BASE_DIR / 'har-files'
RESULTS_DIR = BASE_DIR / 'results'
PERSITE_DIR = RESULTS_DIR / 'per-site'
FIGURES_DIR = BASE_DIR / 'paper' / 'figures'

# Anti-pattern thresholds
ANON_MAP_FILE = BASE_DIR / 'anonymize_map.json'

OVERSIZED_PAYLOAD_BYTES = 100_000      # 100KB
OVERSIZED_ARRAY_ITEMS = 100            # JSON arrays > 100 items
UNCOMPRESSED_THRESHOLD_BYTES = 1_000   # 1KB -- flag uncompressed responses above this
REDUNDANT_CALL_THRESHOLD = 2           # Same URL called 2+ times = redundant
N_PLUS_1_MIN_BURST = 3                 # 3+ sequential calls to same pattern = N+1

# Quality score weights (must sum to 100)
SCORE_WEIGHTS = {
    'redundant_calls':        15,
    'n_plus_1':               10,
    'sequential_waterfalls':  10,
    'missing_cache_headers':  15,
    'oversized_payloads':     15,
    'missing_compression':    10,
    'third_party_overhead':   15,
    'error_rate':             10,
}

# --- HAR Parsing -------------------------------------------------------------

def load_har(har_path):
    """Load and validate a HAR file. Returns entries list or None."""
    try:
        with open(har_path, 'r', encoding='utf-8', errors='replace') as f:
            data = json.load(f)
        entries = data.get('log', {}).get('entries', [])
        return entries if len(entries) > 0 else None
    except (json.JSONDecodeError, KeyError, FileNotFoundError) as e:
        print(f"  WARNING: Cannot parse {har_path}: {e}")
        return None


def parse_entry(entry):
    """Extract relevant fields from a single HAR entry."""
    req = entry.get('request', {})
    resp = entry.get('response', {})
    timings = entry.get('timings', {})

    url = req.get('url', '')
    parsed = urlparse(url)

    # Response headers as dict
    resp_headers = {}
    for h in resp.get('headers', []):
        resp_headers[h['name'].lower()] = h['value']

    req_headers = {}
    for h in req.get('headers', []):
        req_headers[h['name'].lower()] = h['value']

    # Determine resource type from content-type header
    content_type = resp_headers.get('content-type', '')

    # Response size
    body_size = resp.get('bodySize', 0)
    if body_size <= 0:
        body_size = resp.get('content', {}).get('size', 0)
    if body_size < 0:
        body_size = 0

    # Transfer size (compressed)
    transfer_size = resp.get('_transferSize', body_size)
    if transfer_size < 0:
        transfer_size = 0

    # Timing
    started = entry.get('startedDateTime', '')
    time_ms = entry.get('time', 0)
    if time_ms < 0:
        time_ms = 0

    return {
        'url': url,
        'method': req.get('method', 'GET'),
        'status': resp.get('status', 0),
        'domain': parsed.netloc,
        'path': parsed.path,
        'query': parsed.query,
        'content_type': content_type,
        'body_size': body_size,
        'transfer_size': transfer_size,
        'time_ms': time_ms,
        'started': started,
        'resp_headers': resp_headers,
        'req_headers': req_headers,
        'cache_control': resp_headers.get('cache-control', ''),
        'etag': resp_headers.get('etag', ''),
        'last_modified': resp_headers.get('last-modified', ''),
        'content_encoding': resp_headers.get('content-encoding', ''),
        'is_api': is_api_call(url, content_type, req_headers),
    }


def is_api_call(url, content_type, req_headers):
    """Heuristic: Is this an XHR/fetch API call (not a static asset)?"""
    ct = content_type.lower()

    # JSON responses are almost always API calls
    if 'application/json' in ct or 'application/graphql' in ct:
        return True

    # XHR/fetch indicators in request headers
    if req_headers.get('x-requested-with', '').lower() == 'xmlhttprequest':
        return True
    if 'application/json' in req_headers.get('accept', '').lower():
        return True
    if 'application/json' in req_headers.get('content-type', '').lower():
        return True

    # URL pattern heuristics
    url_lower = url.lower()
    api_patterns = ['/api/', '/graphql', '/v1/', '/v2/', '/v3/', '/ajax/',
                    '/rest/', '/_next/data/', '/wp-json/']
    for pattern in api_patterns:
        if pattern in url_lower:
            return True

    return False


# --- Anti-Pattern Detectors --------------------------------------------------

def detect_redundant_calls(entries):
    """Detect identical API calls made multiple times in one session."""
    api_entries = [e for e in entries if e['is_api']]
    url_counts = Counter()
    for e in api_entries:
        # Normalize: URL without fragment
        key = f"{e['method']}:{e['url'].split('#')[0]}"
        url_counts[key] += 1

    redundant = []
    for key, count in url_counts.items():
        if count >= REDUNDANT_CALL_THRESHOLD:
            method, url = key.split(':', 1)
            redundant.append({
                'url': url[:200],
                'method': method,
                'count': count,
                'excess': count - 1
            })

    return {
        'count': len(redundant),
        'total_excess_calls': sum(r['excess'] for r in redundant),
        'details': redundant
    }


def detect_n_plus_1(entries):
    """Detect N+1 patterns: bursts of calls to the same URL pattern with varying IDs."""
    api_entries = [e for e in entries if e['is_api']]

    # Group by URL pattern (replace numeric segments with {id})
    def to_pattern(path):
        return re.sub(r'/\d+', '/{id}', path)

    pattern_groups = defaultdict(list)
    for e in api_entries:
        pattern = f"{e['domain']}{to_pattern(e['path'])}"
        pattern_groups[pattern].append(e)

    n_plus_1 = []
    for pattern, group in pattern_groups.items():
        if len(group) >= N_PLUS_1_MIN_BURST:
            # Check that URLs actually differ (not just same URL repeated -- that's redundant)
            unique_urls = set(e['url'].split('?')[0] for e in group)
            if len(unique_urls) >= N_PLUS_1_MIN_BURST:
                n_plus_1.append({
                    'pattern': pattern[:200],
                    'count': len(group),
                    'example_urls': [e['url'][:150] for e in group[:3]]
                })

    return {
        'count': len(n_plus_1),
        'total_burst_calls': sum(n['count'] for n in n_plus_1),
        'details': n_plus_1
    }


def detect_sequential_waterfalls(entries):
    """Detect API calls that could have been parallelized but were made sequentially."""
    api_entries = [e for e in entries if e['is_api'] and e['started']]

    # Sort by start time
    try:
        api_entries.sort(key=lambda e: e['started'])
    except (TypeError, ValueError):
        return {'count': 0, 'wasted_ms': 0, 'details': []}

    waterfalls = []
    for i in range(1, len(api_entries)):
        prev = api_entries[i - 1]
        curr = api_entries[i]

        # Different domains = likely independent
        if prev['domain'] != curr['domain']:
            continue

        # If current started after previous ended, and they're to different endpoints
        if prev['path'] == curr['path']:
            continue

        # Estimate: if prev finished before curr started
        prev_end_estimate = prev['time_ms']
        if prev_end_estimate > 0 and curr['time_ms'] > 0:
            # Simple heuristic: sequential if very close start times with no overlap
            # We can't do precise timing without absolute timestamps, so flag
            # same-domain sequential calls to different endpoints
            waterfalls.append({
                'prev_url': prev['url'][:150],
                'curr_url': curr['url'][:150],
                'prev_time_ms': prev['time_ms'],
                'curr_time_ms': curr['time_ms'],
                'potential_saving_ms': min(prev['time_ms'], curr['time_ms'])
            })

    # Only report significant waterfalls (top 10 by potential savings)
    waterfalls.sort(key=lambda w: w['potential_saving_ms'], reverse=True)
    top_waterfalls = waterfalls[:10]

    return {
        'count': len(waterfalls),
        'wasted_ms': sum(w['potential_saving_ms'] for w in top_waterfalls),
        'details': top_waterfalls
    }


def detect_missing_cache_headers(entries):
    """Detect API responses with no caching guidance."""
    api_entries = [e for e in entries if e['is_api'] and e['status'] == 200]
    if not api_entries:
        return {'count': 0, 'percentage': 0, 'details': []}

    missing = []
    for e in api_entries:
        has_cache_control = bool(e['cache_control'])
        has_etag = bool(e['etag'])
        has_last_modified = bool(e['last_modified'])

        if not has_cache_control and not has_etag and not has_last_modified:
            missing.append({
                'url': e['url'][:200],
                'status': e['status']
            })

    return {
        'count': len(missing),
        'total_api_responses': len(api_entries),
        'percentage': round(len(missing) / len(api_entries) * 100, 1) if api_entries else 0,
        'details': missing[:20]  # Limit details
    }


def detect_oversized_payloads(entries):
    """Detect API responses that are unusually large (overfetching)."""
    api_entries = [e for e in entries if e['is_api'] and e['body_size'] > 0]

    oversized = []
    for e in api_entries:
        if e['body_size'] > OVERSIZED_PAYLOAD_BYTES:
            oversized.append({
                'url': e['url'][:200],
                'body_size_kb': round(e['body_size'] / 1024, 1),
                'content_type': e['content_type'][:50]
            })

    total_excess_kb = sum(
        (e['body_size'] - OVERSIZED_PAYLOAD_BYTES) / 1024
        for e in api_entries if e['body_size'] > OVERSIZED_PAYLOAD_BYTES
    )

    return {
        'count': len(oversized),
        'total_excess_kb': round(total_excess_kb, 1),
        'details': oversized
    }


def detect_missing_compression(entries):
    """Detect API responses that aren't compressed but should be."""
    api_entries = [e for e in entries if e['is_api'] and e['body_size'] > UNCOMPRESSED_THRESHOLD_BYTES]

    uncompressed = []
    for e in api_entries:
        encoding = e['content_encoding'].lower()
        if not encoding or encoding == 'identity':
            uncompressed.append({
                'url': e['url'][:200],
                'body_size_kb': round(e['body_size'] / 1024, 1),
                'potential_savings_kb': round(e['body_size'] * 0.7 / 1024, 1)  # ~70% compression ratio
            })

    return {
        'count': len(uncompressed),
        'potential_savings_kb': round(sum(u['potential_savings_kb'] for u in uncompressed), 1),
        'details': uncompressed[:20]
    }


def detect_third_party_overhead(entries, site_domain):
    """Classify requests as first-party vs third-party and measure overhead."""
    if not entries:
        return {'percentage_count': 0, 'percentage_bytes': 0, 'categories': {}, 'details': []}

    # Extract main domain (e.g., "example.com" from "www.example.com")
    main_domain_parts = site_domain.split('.')
    if len(main_domain_parts) >= 2:
        main_domain = '.'.join(main_domain_parts[-2:])
    else:
        main_domain = site_domain

    first_party = []
    third_party = []

    # Known third-party categories
    tp_categories = {
        'analytics': ['google-analytics', 'googletagmanager', 'analytics', 'hotjar',
                      'mixpanel', 'segment', 'amplitude', 'heap', 'fullstory',
                      'mouseflow', 'clarity.ms', 'newrelic', 'datadoghq'],
        'ads': ['doubleclick', 'googlesyndication', 'googleadservices', 'adsystem',
                'adnxs', 'criteo', 'taboola', 'outbrain', 'amazon-adsystem',
                'facebook.com/tr', 'ads-twitter', 'moatads'],
        'social': ['facebook.net', 'twitter.com', 'platform.twitter', 'connect.facebook',
                   'instagram', 'linkedin', 'pinterest.com/v3'],
        'cdn': ['cloudflare', 'cloudfront', 'akamai', 'fastly', 'jsdelivr',
                'cdnjs', 'unpkg', 'googleapis.com/ajax'],
        'tracking': ['pixel', 'beacon', 'tracker', 'collect', 'log.',
                     'telemetry', 'events.', 'metrics.'],
    }

    for e in entries:
        domain = e['domain'].lower()
        if main_domain.lower() in domain:
            first_party.append(e)
        else:
            # Categorize
            category = 'other'
            for cat, patterns in tp_categories.items():
                if any(p in domain or p in e['url'].lower() for p in patterns):
                    category = cat
                    break
            e['tp_category'] = category
            third_party.append(e)

    total_count = len(first_party) + len(third_party)
    total_bytes = sum(e['transfer_size'] for e in first_party) + sum(e['transfer_size'] for e in third_party)

    tp_count_pct = round(len(third_party) / total_count * 100, 1) if total_count else 0
    tp_bytes = sum(e['transfer_size'] for e in third_party)
    tp_bytes_pct = round(tp_bytes / total_bytes * 100, 1) if total_bytes else 0

    # Category breakdown
    cat_counts = Counter(e.get('tp_category', 'other') for e in third_party)

    return {
        'first_party_count': len(first_party),
        'third_party_count': len(third_party),
        'percentage_count': tp_count_pct,
        'percentage_bytes': tp_bytes_pct,
        'third_party_bytes_kb': round(tp_bytes / 1024, 1),
        'categories': dict(cat_counts),
        'details': []
    }


def detect_error_responses(entries):
    """Detect API calls returning errors."""
    api_entries = [e for e in entries if e['is_api']]
    if not api_entries:
        return {'count': 0, 'percentage': 0, 'details': []}

    errors = [e for e in api_entries if e['status'] >= 400]

    return {
        'count': len(errors),
        'total_api_calls': len(api_entries),
        'percentage': round(len(errors) / len(api_entries) * 100, 1) if api_entries else 0,
        'by_status': dict(Counter(e['status'] for e in errors)),
        'details': [{'url': e['url'][:200], 'status': e['status']} for e in errors[:10]]
    }


# --- Scoring -----------------------------------------------------------------

def compute_quality_score(analysis):
    """Compute 0-100 quality score from anti-pattern analysis."""
    scores = {}

    # Redundant calls: 0 = perfect, 10+ = worst
    rc = analysis['redundant_calls']['total_excess_calls']
    scores['redundant_calls'] = max(0, 100 - rc * 10)

    # N+1: 0 = perfect, 5+ patterns = worst
    np = analysis['n_plus_1']['count']
    scores['n_plus_1'] = max(0, 100 - np * 20)

    # Sequential waterfalls: based on wasted time
    wf = analysis['sequential_waterfalls']['wasted_ms']
    scores['sequential_waterfalls'] = max(0, 100 - wf / 50)

    # Missing cache headers: percentage-based
    mc = analysis['missing_cache_headers']['percentage']
    scores['missing_cache_headers'] = max(0, 100 - mc)

    # Oversized payloads: 0 = perfect, 5+ = worst
    op = analysis['oversized_payloads']['count']
    scores['oversized_payloads'] = max(0, 100 - op * 15)

    # Missing compression: based on potential savings
    mcomp = analysis['missing_compression']['potential_savings_kb']
    scores['missing_compression'] = max(0, 100 - mcomp / 5)

    # Third-party overhead: lower is better
    tp = analysis['third_party_overhead']['percentage_count']
    scores['third_party_overhead'] = max(0, 100 - tp)

    # Error rate
    er = analysis['error_responses']['percentage']
    scores['error_rate'] = max(0, 100 - er * 5)

    # Weighted average
    total_score = 0
    for dimension, weight in SCORE_WEIGHTS.items():
        s = max(0, min(100, scores.get(dimension, 100)))
        total_score += s * (weight / 100)

    return {
        'total': round(total_score, 1),
        'dimensions': {k: round(v, 1) for k, v in scores.items()}
    }


# --- Analyze One HAR File ----------------------------------------------------

def analyze_har(har_path, site_domain):
    """Run all detectors on a single HAR file."""
    raw_entries = load_har(har_path)
    if raw_entries is None:
        return None

    entries = [parse_entry(e) for e in raw_entries]

    analysis = {
        'total_requests': len(entries),
        'api_requests': sum(1 for e in entries if e['is_api']),
        'total_bytes': sum(e['transfer_size'] for e in entries),
        'api_bytes': sum(e['transfer_size'] for e in entries if e['is_api']),
        'unique_domains': len(set(e['domain'] for e in entries)),
        'redundant_calls': detect_redundant_calls(entries),
        'n_plus_1': detect_n_plus_1(entries),
        'sequential_waterfalls': detect_sequential_waterfalls(entries),
        'missing_cache_headers': detect_missing_cache_headers(entries),
        'oversized_payloads': detect_oversized_payloads(entries),
        'missing_compression': detect_missing_compression(entries),
        'third_party_overhead': detect_third_party_overhead(entries, site_domain),
        'error_responses': detect_error_responses(entries),
    }

    analysis['quality_score'] = compute_quality_score(analysis)

    return analysis


# --- Analyze One Site (All HAR Files) ----------------------------------------

def analyze_site(site_id):
    """Analyze all HAR files for a single site, return aggregated report."""
    site_dir = HAR_DIR / site_id
    if not site_dir.exists():
        print(f"  WARNING: No HAR directory for {site_id}")
        return None

    # Load site metadata from capture log
    capture_log_path = site_dir / 'capture_log.json'
    metadata = {}
    if capture_log_path.exists():
        with open(capture_log_path, 'r') as f:
            metadata = json.load(f)

    # Skip blocked/failed sites
    site_status = metadata.get('status', 'unknown')
    if site_status in ('blocked', 'failed'):
        print(f"  SKIP {site_id}: status={site_status}")
        return None

    # Skip sites where all captures returned non-200 (e.g. 401 paywall)
    captures = metadata.get('captures', [])
    if captures:
        statuses = [c.get('httpStatus', 0) for c in captures]
        if all(s != 200 for s in statuses):
            print(f"  SKIP {site_id}: all captures returned non-200 HTTP statuses {set(statuses)}")
            return None

    # Get the site's main domain
    pages = metadata.get('page_statuses', [])
    site_domain = ''
    if pages:
        site_domain = urlparse(pages[0].get('url', '')).netloc

    # Find all HAR files
    har_files = sorted(site_dir.glob('*.har'))
    if not har_files:
        print(f"  WARNING: No HAR files found in {site_dir}")
        return None

    print(f"  Analyzing {site_id}: {len(har_files)} HAR files...")

    # Analyze each HAR file
    page_analyses = []
    for har_file in har_files:
        result = analyze_har(har_file, site_domain)
        if result:
            # Parse filename: <page>_run<N>_<cold|warm>.har
            fname = har_file.stem
            parts = fname.rsplit('_', 2)
            page_label = parts[0] if len(parts) >= 3 else fname
            run_num = parts[1] if len(parts) >= 3 else '1'
            visit_type = parts[2] if len(parts) >= 3 else 'cold'

            result['file'] = har_file.name
            result['page'] = page_label
            result['run'] = run_num
            result['visit_type'] = visit_type
            page_analyses.append(result)

    if not page_analyses:
        return None

    # Aggregate across all captures for this site
    cold_analyses = [a for a in page_analyses if a['visit_type'] == 'cold']

    # Use cold-visit averages for scoring (cold = realistic first visit)
    if cold_analyses:
        avg_score = sum(a['quality_score']['total'] for a in cold_analyses) / len(cold_analyses)
        avg_requests = sum(a['total_requests'] for a in cold_analyses) / len(cold_analyses)
        avg_api = sum(a['api_requests'] for a in cold_analyses) / len(cold_analyses)
        avg_bytes = sum(a['total_bytes'] for a in cold_analyses) / len(cold_analyses)
    else:
        avg_score = sum(a['quality_score']['total'] for a in page_analyses) / len(page_analyses)
        avg_requests = sum(a['total_requests'] for a in page_analyses) / len(page_analyses)
        avg_api = sum(a['api_requests'] for a in page_analyses) / len(page_analyses)
        avg_bytes = sum(a['total_bytes'] for a in page_analyses) / len(page_analyses)

    # Aggregate dimension scores
    dim_scores = defaultdict(list)
    source = cold_analyses if cold_analyses else page_analyses
    for a in source:
        for dim, val in a['quality_score']['dimensions'].items():
            dim_scores[dim].append(val)
    avg_dims = {dim: round(sum(vals)/len(vals), 1) for dim, vals in dim_scores.items()}

    # Aggregate anti-pattern counts
    avg_redundant = sum(a['redundant_calls']['total_excess_calls'] for a in source) / len(source)
    avg_n1 = sum(a['n_plus_1']['count'] for a in source) / len(source)
    avg_cache_pct = sum(a['missing_cache_headers']['percentage'] for a in source) / len(source)
    avg_oversized = sum(a['oversized_payloads']['count'] for a in source) / len(source)
    avg_compression = sum(a['missing_compression']['count'] for a in source) / len(source)
    avg_tp_pct = sum(a['third_party_overhead']['percentage_count'] for a in source) / len(source)
    avg_error_pct = sum(a['error_responses']['percentage'] for a in source) / len(source)

    site_report = {
        'site_id': site_id,
        'site_name': metadata.get('site_name', site_id),
        'category': metadata.get('category', 'unknown'),
        'architecture': metadata.get('architecture', 'unknown'),
        'status': site_status,
        'har_files_analyzed': len(page_analyses),
        'summary': {
            'avg_total_requests': round(avg_requests, 1),
            'avg_api_requests': round(avg_api, 1),
            'avg_total_bytes_kb': round(avg_bytes / 1024, 1),
            'quality_score': round(avg_score, 1),
        },
        'dimension_scores': avg_dims,
        'anti_pattern_averages': {
            'redundant_excess_calls': round(avg_redundant, 1),
            'n_plus_1_patterns': round(avg_n1, 1),
            'missing_cache_pct': round(avg_cache_pct, 1),
            'oversized_payloads': round(avg_oversized, 1),
            'uncompressed_responses': round(avg_compression, 1),
            'third_party_pct': round(avg_tp_pct, 1),
            'error_rate_pct': round(avg_error_pct, 1),
        },
        'per_capture': page_analyses,
        'analyzed_at': datetime.now().isoformat()
    }

    return site_report


# --- Generate Paper Tables (CSV) ---------------------------------------------

def generate_tables(all_reports):
    """Generate paper-ready CSV tables from all site reports."""

    # Table 1: Site Quality Scores (main results table)
    rows = []
    for r in all_reports:
        row = {
            'Site': r['site_name'],
            'Category': r['category'],
            'Architecture': r['architecture'],
            'Avg Requests': r['summary']['avg_total_requests'],
            'Avg API Calls': r['summary']['avg_api_requests'],
            'Page Size (KB)': r['summary']['avg_total_bytes_kb'],
            'Quality Score': r['summary']['quality_score'],
            'Redundant Calls': r['anti_pattern_averages']['redundant_excess_calls'],
            'N+1 Patterns': r['anti_pattern_averages']['n_plus_1_patterns'],
            'Missing Cache %': r['anti_pattern_averages']['missing_cache_pct'],
            'Oversized': r['anti_pattern_averages']['oversized_payloads'],
            'Uncompressed': r['anti_pattern_averages']['uncompressed_responses'],
            '3rd Party %': r['anti_pattern_averages']['third_party_pct'],
            'Error Rate %': r['anti_pattern_averages']['error_rate_pct'],
        }
        rows.append(row)

    df_scores = pd.DataFrame(rows).sort_values('Quality Score', ascending=True)
    scores_path = RESULTS_DIR / 'site_scores.csv'
    df_scores.to_csv(scores_path, index=False)
    print(f"  Saved: {scores_path}")

    # Table 2: Summary statistics across all sites
    numeric_cols = ['Quality Score', 'Avg Requests', 'Avg API Calls', 'Page Size (KB)',
                    'Redundant Calls', 'N+1 Patterns', 'Missing Cache %',
                    'Oversized', 'Uncompressed', '3rd Party %', 'Error Rate %']

    stats_rows = []
    for col in numeric_cols:
        vals = df_scores[col].dropna()
        stats_rows.append({
            'Metric': col,
            'Mean': round(vals.mean(), 1),
            'Median': round(vals.median(), 1),
            'Std Dev': round(vals.std(), 1),
            'Min': round(vals.min(), 1),
            'Max': round(vals.max(), 1),
        })

    df_stats = pd.DataFrame(stats_rows)
    stats_path = RESULTS_DIR / 'summary_stats.csv'
    df_stats.to_csv(stats_path, index=False)
    print(f"  Saved: {stats_path}")

    # Table 3: Anti-pattern frequency (for paper discussion)
    antipattern_rows = []
    for r in all_reports:
        for capture in r['per_capture']:
            if capture['visit_type'] != 'cold':
                continue
            antipattern_rows.append({
                'Site': r['site_name'],
                'Page': capture['page'],
                'Run': capture['run'],
                'Total Requests': capture['total_requests'],
                'API Requests': capture['api_requests'],
                'Redundant Calls': capture['redundant_calls']['total_excess_calls'],
                'N+1 Patterns': capture['n_plus_1']['count'],
                'Missing Cache %': capture['missing_cache_headers']['percentage'],
                'Oversized Payloads': capture['oversized_payloads']['count'],
                'Uncompressed': capture['missing_compression']['count'],
                '3rd Party %': capture['third_party_overhead']['percentage_count'],
                'Error Rate %': capture['error_responses']['percentage'],
                'Quality Score': capture['quality_score']['total'],
            })

    df_antipatterns = pd.DataFrame(antipattern_rows)
    ap_path = RESULTS_DIR / 'anti_patterns.csv'
    df_antipatterns.to_csv(ap_path, index=False)
    print(f"  Saved: {ap_path}")

    return df_scores, df_stats, df_antipatterns


# --- Generate Paper Figures --------------------------------------------------

def generate_figures(df_scores, df_stats, df_antipatterns, all_reports):
    """Generate publication-ready matplotlib figures with consistent styling."""
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)

    # ── Consistent Paper Theme ──────────────────────────────────────────────
    # Unified color palette (Tableau-inspired, colorblind-safe)
    PALETTE = {
        'primary': '#2C6FAC',      # Strong blue
        'secondary': '#E8832A',    # Warm orange
        'accent1': '#3FA34D',      # Green
        'accent2': '#C23B22',      # Red
        'accent3': '#7B4F9E',      # Purple
        'accent4': '#D4A843',      # Gold
        'neutral': '#6B7B8D',      # Steel gray
        'light_bg': '#F7F9FB',     # Very light blue-gray
    }
    # Score-tier gradient (red -> orange -> teal -> blue)
    SCORE_COLORS = {
        'low': '#C23B22',          # <60
        'mid_low': '#E8832A',      # 60-75
        'mid_high': '#3FA34D',     # 75-90
        'high': '#2C6FAC',         # 90+
    }
    # Category palette for stacked/grouped charts
    CAT_COLORS = ['#2C6FAC', '#C23B22', '#7B4F9E', '#3FA34D', '#E8832A', '#6B7B8D']

    def score_color(s):
        if s < 60: return SCORE_COLORS['low']
        if s < 75: return SCORE_COLORS['mid_low']
        if s < 90: return SCORE_COLORS['mid_high']
        return SCORE_COLORS['high']

    plt.rcParams.update({
        'figure.dpi': 300,
        'savefig.dpi': 300,
        'font.family': 'sans-serif',
        'font.sans-serif': ['Arial', 'Helvetica', 'DejaVu Sans'],
        'font.size': 10,
        'axes.titlesize': 13,
        'axes.titleweight': 'bold',
        'axes.labelsize': 11,
        'axes.edgecolor': '#333333',
        'axes.linewidth': 0.8,
        'xtick.labelsize': 9,
        'ytick.labelsize': 9,
        'legend.fontsize': 9,
        'figure.figsize': (10, 6),
        'figure.facecolor': 'white',
        'savefig.bbox': 'tight',
        'savefig.facecolor': 'white',
        'grid.alpha': 0.3,
        'grid.linewidth': 0.5,
    })
    sns.set_theme(style='whitegrid')

    if df_scores.empty:
        print("  WARNING: No data to plot")
        return

    # -- Figure 1: Quality Score by Site (horizontal bar) --
    fig, ax = plt.subplots(figsize=(10, max(6, len(df_scores) * 0.42)))
    colors = [score_color(s) for s in df_scores['Quality Score']]
    bars = ax.barh(df_scores['Site'], df_scores['Quality Score'], color=colors,
                   edgecolor='white', linewidth=0.5, height=0.7)
    ax.set_xlabel('Quality Score (0--100)')
    ax.set_title('API Call Quality Score by Website')
    ax.set_xlim(0, 105)
    ax.axvline(x=df_scores['Quality Score'].median(), color=PALETTE['neutral'],
               linestyle='--', alpha=0.6, linewidth=1)
    ax.text(df_scores['Quality Score'].median() + 1, len(df_scores) - 0.5,
            f'Median: {df_scores["Quality Score"].median():.1f}',
            fontsize=8, color=PALETTE['neutral'], va='top')
    for bar, score in zip(bars, df_scores['Quality Score']):
        ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height()/2,
                f'{score:.1f}', va='center', fontsize=8, fontweight='bold')
    ax.invert_yaxis()
    sns.despine(left=True)
    plt.tight_layout()
    fig.savefig(FIGURES_DIR / 'fig1_quality_scores.png')
    fig.savefig(FIGURES_DIR / 'fig1_quality_scores.pdf')
    plt.close()
    print(f"  Saved: fig1_quality_scores.png/pdf")

    # -- Figure 2: Anti-pattern heatmap --
    dims = ['Redundant Calls', 'N+1 Patterns', 'Missing Cache %',
            'Oversized', 'Uncompressed', '3rd Party %', 'Error Rate %']
    available_dims = [d for d in dims if d in df_scores.columns]
    if available_dims:
        heatmap_data = df_scores.set_index('Site')[available_dims]
        fig, ax = plt.subplots(figsize=(12, max(6, len(df_scores) * 0.42)))
        cmap = sns.color_palette("YlOrRd", as_cmap=True)
        sns.heatmap(heatmap_data, annot=True, fmt='.1f', cmap=cmap,
                    linewidths=0.8, linecolor='white', ax=ax,
                    cbar_kws={'label': 'Anti-Pattern Severity', 'shrink': 0.8})
        ax.set_title('Anti-Pattern Prevalence by Website')
        ax.set_yticklabels(ax.get_yticklabels(), rotation=0)
        plt.tight_layout()
        fig.savefig(FIGURES_DIR / 'fig2_antipattern_heatmap.png')
        fig.savefig(FIGURES_DIR / 'fig2_antipattern_heatmap.pdf')
        plt.close()
        print(f"  Saved: fig2_antipattern_heatmap.png/pdf")

    # -- Figure 3: Category comparison (strip + box) --
    if len(df_scores['Category'].unique()) > 1:
        fig, ax = plt.subplots(figsize=(12, 6))
        category_order = df_scores.groupby('Category')['Quality Score'].median().sort_values().index
        sns.boxplot(data=df_scores, x='Category', y='Quality Score', order=category_order,
                    ax=ax, color=PALETTE['light_bg'], linewidth=1.2,
                    fliersize=0, boxprops=dict(edgecolor=PALETTE['primary']),
                    medianprops=dict(color=PALETTE['accent2'], linewidth=2),
                    whiskerprops=dict(color=PALETTE['primary']),
                    capprops=dict(color=PALETTE['primary']))
        sns.stripplot(data=df_scores, x='Category', y='Quality Score', order=category_order,
                      ax=ax, color=PALETTE['primary'], size=8, alpha=0.7, jitter=0.15)
        ax.set_title('Quality Score Distribution by Website Category')
        ax.set_xlabel('')
        ax.set_ylabel('Quality Score (0--100)')
        ax.set_ylim(40, 105)
        plt.xticks(rotation=40, ha='right')
        sns.despine()
        plt.tight_layout()
        fig.savefig(FIGURES_DIR / 'fig3_category_comparison.png')
        fig.savefig(FIGURES_DIR / 'fig3_category_comparison.pdf')
        plt.close()
        print(f"  Saved: fig3_category_comparison.png/pdf")

    # -- Figure 4: Requests vs Quality Score (scatter) --
    fig, ax = plt.subplots(figsize=(10, 6))
    scatter = ax.scatter(df_scores['Avg Requests'], df_scores['Quality Score'],
                        c=df_scores['3rd Party %'], cmap='RdYlBu',
                        s=120, edgecolors='#333333', linewidth=0.6, zorder=5)
    cbar = plt.colorbar(scatter, label='Third-Party Request %', shrink=0.85)
    cbar.ax.tick_params(labelsize=8)
    for _, row in df_scores.iterrows():
        ax.annotate(row['Site'], (row['Avg Requests'] * 1.03, row['Quality Score'] + 0.8),
                   fontsize=7, ha='left', va='bottom', color='#333333')
    ax.set_xlabel('Average Total Requests per Page Load')
    ax.set_ylabel('Quality Score (0--100)')
    ax.set_title('Request Volume vs. API Call Quality')
    ax.set_ylim(50, 105)
    sns.despine()
    plt.tight_layout()
    fig.savefig(FIGURES_DIR / 'fig4_requests_vs_quality.png')
    fig.savefig(FIGURES_DIR / 'fig4_requests_vs_quality.pdf')
    plt.close()
    print(f"  Saved: fig4_requests_vs_quality.png/pdf")

    # -- Figure 5: Third-party breakdown (stacked bar) --
    tp_data = []
    for r in all_reports:
        cats = defaultdict(int)
        for capture in r['per_capture']:
            if capture['visit_type'] != 'cold':
                continue
            for cat, count in capture['third_party_overhead'].get('categories', {}).items():
                cats[cat] += count
        if cats:
            total = sum(cats.values())
            tp_data.append({
                'Site': r['site_name'],
                **{cat: round(count/total*100, 1) for cat, count in cats.items()}
            })

    if tp_data:
        df_tp = pd.DataFrame(tp_data).fillna(0).set_index('Site')
        all_cats = ['analytics', 'ads', 'social', 'cdn', 'tracking', 'other']
        plot_cats = [c for c in all_cats if c in df_tp.columns]
        if plot_cats:
            df_tp = df_tp[plot_cats]
            fig, ax = plt.subplots(figsize=(12, max(6, len(df_tp) * 0.42)))
            df_tp.plot(kind='barh', stacked=True, ax=ax, color=CAT_COLORS[:len(plot_cats)],
                      edgecolor='white', linewidth=0.3)
            ax.set_xlabel('Third-Party Request Distribution (%)')
            ax.set_title('Third-Party Request Categories by Website')
            ax.legend(title='Category', bbox_to_anchor=(1.02, 1), loc='upper left',
                     frameon=True, fancybox=True, shadow=False)
            sns.despine(left=True)
            plt.tight_layout()
            fig.savefig(FIGURES_DIR / 'fig5_thirdparty_breakdown.png')
            fig.savefig(FIGURES_DIR / 'fig5_thirdparty_breakdown.pdf')
            plt.close()
            print(f"  Saved: fig5_thirdparty_breakdown.png/pdf")

    # -- Figure 6: Best vs Worst comparison (grouped bar) --
    if len(df_scores) >= 6:
        dim_cols = ['Redundant Calls', 'Missing Cache %',
                    'Oversized', 'Uncompressed', '3rd Party %', 'Error Rate %']
        available = [c for c in dim_cols if c in df_scores.columns]

        if len(available) >= 3:
            sorted_df = df_scores.sort_values('Quality Score', ascending=False)
            top3 = sorted_df.head(3)
            bottom3 = sorted_df.tail(3)

            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6), sharey=True)
            x = range(len(available))
            width = 0.25

            # Top 3 sites
            for i, (_, row) in enumerate(top3.iterrows()):
                ax1.bar([xi + i*width for xi in x], [row[c] for c in available],
                       width=width, alpha=0.85, label=row['Site'],
                       color=CAT_COLORS[i], edgecolor='white', linewidth=0.5)
            ax1.set_title('Top 3 Sites (Highest Quality)', fontweight='bold')
            ax1.legend(fontsize=8, frameon=True)
            ax1.set_ylabel('Anti-Pattern Count / Percentage')
            ax1.set_xticks([xi + width for xi in x])
            ax1.set_xticklabels(available, rotation=40, ha='right', fontsize=8)

            # Bottom 3 sites
            for i, (_, row) in enumerate(bottom3.iterrows()):
                ax2.bar([xi + i*width for xi in x], [row[c] for c in available],
                       width=width, alpha=0.85, label=row['Site'],
                       color=CAT_COLORS[i+3], edgecolor='white', linewidth=0.5)
            ax2.set_title('Bottom 3 Sites (Lowest Quality)', fontweight='bold')
            ax2.legend(fontsize=8, frameon=True)
            ax2.set_xticks([xi + width for xi in x])
            ax2.set_xticklabels(available, rotation=40, ha='right', fontsize=8)

            plt.suptitle('Anti-Pattern Comparison: Best vs. Worst Performing Sites',
                        fontweight='bold', fontsize=13)
            sns.despine()
            plt.tight_layout()
            fig.savefig(FIGURES_DIR / 'fig6_best_vs_worst.png')
            fig.savefig(FIGURES_DIR / 'fig6_best_vs_worst.pdf')
            plt.close()
            print(f"  Saved: fig6_best_vs_worst.png/pdf")


# --- Main --------------------------------------------------------------------

def load_anonymization_map():
    """Load site anonymization mapping from anonymize_map.json."""
    if not ANON_MAP_FILE.exists():
        print("ERROR: anonymize_map.json not found.")
        sys.exit(1)
    with open(ANON_MAP_FILE, 'r') as f:
        data = json.load(f)
    # Build lookup: site_id -> pseudonym
    mapping = {}
    for site_id, info in data.get('analyzed_sites', {}).items():
        mapping[site_id] = info['pseudonym']
    for site_id, info in data.get('excluded_sites', {}).items():
        mapping[site_id] = info['pseudonym']
    # Also build name -> pseudonym for display name lookups
    name_mapping = {}
    for site_id, info in data.get('analyzed_sites', {}).items():
        name_mapping[info['original_name']] = info['pseudonym']
    for site_id, info in data.get('excluded_sites', {}).items():
        name_mapping[info['original_name']] = info['pseudonym']
    return mapping, name_mapping


def anonymize_report(report, id_map, name_map):
    """Replace site_name and site_id with anonymized pseudonyms in a report."""
    site_id = report.get('site_id', '')
    pseudonym = id_map.get(site_id, report.get('site_name', site_id))
    report['site_name'] = pseudonym
    # Replace site_id with the pseudonym slug so no original ID leaks
    report['anon_id'] = pseudonym.lower()
    report['site_id'] = pseudonym.lower()
    return report


def main():
    args = sys.argv[1:]
    site_filter = None
    figures_only = '--figures-only' in args
    anonymize = '--anonymize' in args

    if '--site' in args:
        idx = args.index('--site')
        site_filter = args[idx + 1] if idx + 1 < len(args) else None

    # Load anonymization map if requested
    anon_id_map, anon_name_map = {}, {}
    if anonymize:
        anon_id_map, anon_name_map = load_anonymization_map()
        print('  Anonymization enabled: site names will be replaced with pseudonyms')

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    PERSITE_DIR.mkdir(parents=True, exist_ok=True)
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)

    if figures_only:
        # Load existing results
        scores_path = RESULTS_DIR / 'site_scores.csv'
        ap_path = RESULTS_DIR / 'anti_patterns.csv'
        stats_path = RESULTS_DIR / 'summary_stats.csv'
        if not scores_path.exists():
            print("ERROR: No existing results found. Run full analysis first.")
            sys.exit(1)
        df_scores = pd.read_csv(scores_path)
        df_stats = pd.read_csv(stats_path)
        df_antipatterns = pd.read_csv(ap_path)

        # Load per-site reports for figure generation
        all_reports = []
        for f in PERSITE_DIR.glob('*.json'):
            with open(f) as fh:
                all_reports.append(json.load(fh))

        print('Regenerating figures from existing results...')
        generate_figures(df_scores, df_stats, df_antipatterns, all_reports)
        return

    # -- Full Analysis --

    # Discover all site directories
    if site_filter:
        site_dirs = [HAR_DIR / site_filter]
    else:
        site_dirs = sorted([d for d in HAR_DIR.iterdir() if d.is_dir() and not d.name.startswith('_')])

    if not site_dirs:
        print("ERROR: No HAR directories found. Run capture.js first.")
        sys.exit(1)

    print('===============================================================')
    print('  Network Call Quality Audit - HAR Analysis')
    print('===============================================================')
    print(f'  Sites to analyze: {len(site_dirs)}')
    print(f'  HAR directory: {HAR_DIR}')
    print(f'  Output: {RESULTS_DIR}')
    print('===============================================================\n')

    all_reports = []

    for site_dir in site_dirs:
        site_id = site_dir.name
        report = analyze_site(site_id)
        if report:
            # Apply anonymization if enabled
            if anonymize:
                report = anonymize_report(report, anon_id_map, anon_name_map)

            all_reports.append(report)

            # Save per-site JSON report
            file_id = report.get('anon_id', site_id) if anonymize else site_id
            report_path = PERSITE_DIR / f'{file_id}.json'
            # Remove per_capture details from saved report to keep file manageable
            save_report = {k: v for k, v in report.items() if k not in ('per_capture', 'anon_id')}
            save_report['captures_analyzed'] = len(report['per_capture'])
            with open(report_path, 'w') as f:
                json.dump(save_report, f, indent=2)

    if not all_reports:
        print("\nERROR: No sites could be analyzed. Check HAR files.")
        sys.exit(1)

    print(f'\n  Successfully analyzed {len(all_reports)} sites')
    print('  Generating tables and figures...\n')

    # Generate tables
    df_scores, df_stats, df_antipatterns = generate_tables(all_reports)

    # Generate figures
    generate_figures(df_scores, df_stats, df_antipatterns, all_reports)

    # Print summary to console
    print('\n===============================================================')
    print('  ANALYSIS COMPLETE')
    print('===============================================================')
    print(f'  Sites analyzed: {len(all_reports)}')
    print(f'\n  RESULTS:')
    print(f'    {RESULTS_DIR / "site_scores.csv"}')
    print(f'    {RESULTS_DIR / "summary_stats.csv"}')
    print(f'    {RESULTS_DIR / "anti_patterns.csv"}')
    print(f'\n  FIGURES:')
    for fig in sorted(FIGURES_DIR.glob('*.png')):
        print(f'    {fig}')
    print('===============================================================')

    # Quick results table
    print('\n  QUALITY RANKING:')
    print('  ' + '-' * 60)
    for _, row in df_scores.iterrows():
        score = row['Quality Score']
        bar = '#' * int(score / 5) + '.' * (20 - int(score / 5))
        print(f'  {row["Site"]:<25} {bar} {score:5.1f}/100')
    print('  ' + '-' * 60)

    avg = df_scores['Quality Score'].mean()
    print(f'\n  Average Quality Score: {avg:.1f}/100')
    print(f'  Best:  {df_scores.iloc[-1]["Site"]} ({df_scores.iloc[-1]["Quality Score"]:.1f})')
    print(f'  Worst: {df_scores.iloc[0]["Site"]} ({df_scores.iloc[0]["Quality Score"]:.1f})')


if __name__ == '__main__':
    main()
