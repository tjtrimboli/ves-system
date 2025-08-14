# lev_calculator.py
# Python 3.9+
from __future__ import annotations

import dataclasses
import datetime as dt
import math
import time
from typing import Dict, List, Optional, Tuple

import requests


# ---------------------------
# Constants (documented sources)
# ---------------------------
EPSS_API = "https://api.first.org/data/v1/epss"
# EPSS historical scores are available beginning 2021-04-14 (EPSS v1 start).  ⟶ FIRST docs
EPSS_START_DATE = dt.date(2021, 4, 14)  # https://www.first.org/epss/api
# NVD CVE API v2.0
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"  # https://nvd.nist.gov/developers/vulnerabilities

WINDOW_DAYS = 30  # NIST LEV uses w = 30-day windows


# ---------------------------
# Small helpers
# ---------------------------
def _parse_date(s: str) -> dt.date:
    # NVD "published" is ISO-8601 with time; EPSS "date" is YYYY-MM-DD
    if "T" in s:
        return dt.date.fromisoformat(s.split("T", 1)[0])
    return dt.date.fromisoformat(s)


def daterange(start: dt.date, end: dt.date, step_days: int) -> List[dt.date]:
    """Inclusive start; produce window start dates at fixed step until end."""
    dates = []
    d = start
    while d <= end:
        dates.append(d)
        d += dt.timedelta(days=step_days)
    return dates


def clamp_date(d: dt.date) -> dt.date:
    """Clamp date to EPSS availability floor."""
    return max(d, EPSS_START_DATE)


# ---------------------------
# NVD client
# ---------------------------
def nvd_get_published_date(cve_id: str, api_key: Optional[str] = None) -> dt.date:
    """
    Returns the CVE's NVD 'published' date (UTC date component).
    Uses NVD CVE API v2.0; pass api_key to raise rate limits (header: apiKey).
    """
    headers = {}
    if api_key:
        headers["apiKey"] = api_key  # NVD 2.0 uses 'apiKey' request header (not query string).

    resp = requests.get(NVD_CVE_API, params={"cveId": cve_id}, headers=headers, timeout=30)
    resp.raise_for_status()
    js = resp.json()
    vulns = js.get("vulnerabilities", [])
    if not vulns:
        raise ValueError(f"CVE not found in NVD: {cve_id}")
    published = vulns[0]["cve"]["published"]  # present in the 2.0 schema
    return _parse_date(published)


# ---------------------------
# EPSS client
# ---------------------------
def epss_score_on(cve_id: str, day: dt.date, session: Optional[requests.Session] = None) -> float:
    """
    Get EPSS probability for one CVE on a specific date (probability in [0,1]).
    Uses ?cve= & date= per FIRST EPSS API.
    """
    s = session or requests
    params = {"cve": cve_id, "date": day.isoformat()}
    r = s.get(EPSS_API, params=params, timeout=30)
    r.raise_for_status()
    data = r.json().get("data", [])
    if not data:
        # No score on that date (e.g., pre-publication); treat as 0.0
        return 0.0
    # API returns one row per CVE with fields: cve, epss, percentile, date
    return float(data[0]["epss"])


def epss_scores_daily(
    cve_id: str, start: dt.date, end: dt.date, sleep_secs: float = 0.0
) -> Dict[dt.date, float]:
    """
    Fetch EPSS probability for each day in [start, end], inclusive.
    Note: FIRST API has a built-in 'scope=time-series' but returns only ~30 days;
    LEV2 may span years, so we call per-day. Use a Session + optional sleep for politeness.
    """
    scores: Dict[dt.date, float] = {}
    with requests.Session() as s:
        d = start
        while d <= end:
            scores[d] = epss_score_on(cve_id, d, session=s)
            if sleep_secs:
                time.sleep(sleep_secs)
            d += dt.timedelta(days=1)
    return scores


# ---------------------------
# LEV math (NIST §4)
# ---------------------------
@dataclasses.dataclass
class LevResult:
    lev: float           # LEV (30-day windows)
    lev2: Optional[float]  # LEV2 (daily windows), if computed
    d0: dt.date
    dn: dt.date
    window_starts: List[Tuple[dt.date, float]]  # (window_date, epss_at_date)
    notes: str


def _partial_window_weight(window_start: dt.date, dn: dt.date, w: int = WINDOW_DAYS) -> float:
    """
    Weight for the last (possibly partial) window, per NIST equation:
    multiply the EPSS score by days(window_start, dn)/w if dn falls before window_start+w.
    For all full windows, weight = 1.0.
    """
    window_end = window_start + dt.timedelta(days=w)
    if dn >= window_end:
        return 1.0  # full 30-day window lives entirely in the past
    # partial window length in days (exclusive of end), min(max(0, dn - start), w)
    days_in_partial = max(0, (dn - window_start).days)
    return max(0.0, min(1.0, days_in_partial / float(w)))


def compute_lev(
    cve_id: str,
    nvd_api_key: Optional[str] = None,
    dn: Optional[dt.date] = None,
    compute_lev2: bool = False,
    polite_delay_s: float = 0.0,
) -> LevResult:
    """
    Compute LEV and optionally LEV2 for a CVE.
    - d0: max(CVE published date, EPSS_START_DATE)
    - dn: calculation date (default = today in UTC)
    - LEV  = 1 - Π_i (1 - epss(cve, d_i) * weight_i)
      where d_i are 30-day window starts from d0 to dn, weight_i is 1.0 for full windows
      and weight_last = days(d_last, dn)/30 for the last partial window (if any).
    - LEV2 = 1 - Π_t (1 - epss(cve, t)/30) for each day t in [d0, dn]   (NIST §4.2)
    """
    # 1) Get d0 from NVD (published) and clamp to EPSS start
    published = nvd_get_published_date(cve_id, api_key=nvd_api_key)
    d0 = clamp_date(published)
    # 2) dn default = today (UTC date)
    dn = dn or dt.datetime.utcnow().date()
    if dn < d0:
        raise ValueError(f"dn ({dn}) is earlier than d0 ({d0}).")

    # 3) Build 30-day windows and fetch EPSS for each d_i
    starts = daterange(d0, dn, WINDOW_DAYS)
    epss_by_window: List[Tuple[dt.date, float]] = []
    with requests.Session() as s:
        for d in starts:
            score = epss_score_on(cve_id, d, session=s)
            epss_by_window.append((d, score))
            if polite_delay_s:
                time.sleep(polite_delay_s)

    # 4) Combine via NIST's composite probability with partial-window weight
    #    LEV = 1 - product( (1 - epss_i * weight_i) )
    prod = 1.0
    for (w_start, score) in epss_by_window:
        weight = _partial_window_weight(w_start, dn, WINDOW_DAYS)
        term = max(0.0, min(1.0, 1.0 - (score * weight)))
        prod *= term
    lev = 1.0 - prod

    # 5) Optional LEV2: daily windows
    lev2_value = None
    if compute_lev2:
        # Fetch daily EPSS scores across the entire range
        daily = epss_scores_daily(cve_id, d0, dn, sleep_secs=polite_delay_s)
        prod2 = 1.0
        # NIST: LEV2 = 1 - Π_t (1 - epss(t)/30) across all days t in [d0, dn]
        for day in sorted(daily.keys()):
            daily_weighted = max(0.0, min(1.0, daily[day] / float(WINDOW_DAYS)))
            prod2 *= (1.0 - daily_weighted)
        lev2_value = 1.0 - prod2

    notes = (
        "LEV computed from historical EPSS 30-day probabilities with partial-window correction per NIST CSWP 41 §4. "
        "d0 = max(NVD published date, EPSS start 2021-04-14). EPSS API used for scores; NVD API for metadata."
    )
    return LevResult(
        lev=lev,
        lev2=lev2_value,
        d0=d0,
        dn=dn,
        window_starts=epss_by_window,
        notes=notes,
    )


# ---------------------------
# Example CLI usage
# ---------------------------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="NIST LEV calculator using NVD + EPSS APIs")
    parser.add_argument("cve", help="CVE ID, e.g., CVE-2021-44228")
    parser.add_argument("--nvd-api-key", help="NVD API key (header: apiKey) to increase rate limits", default=None)
    parser.add_argument("--date", help="Calculation date (YYYY-MM-DD). Default: today (UTC).", default=None)
    parser.add_argument("--lev2", action="store_true", help="Also compute LEV2 (daily windows). Makes many EPSS calls.")
    parser.add_argument("--delay", type=float, default=0.0, help="Sleep seconds between API calls (politeness).")
    args = parser.parse_args()

    calc_date = dt.date.fromisoformat(args.date) if args.date else None
    result = compute_lev(
        args.cve,
        nvd_api_key=args.nvd_api_key,
        dn=calc_date,
        compute_lev2=args.lev2,
        polite_delay_s=args.delay,
    )

    print(f"CVE: {args.cve}")
    print(f"d0:  {result.d0}   dn: {result.dn}")
    print(f"LEV: {result.lev:.6f}")
    if result.lev2 is not None:
        print(f"LEV2: {result.lev2:.6f}")
    print()
    print("Window starts and EPSS scores:")
    for d, s in result.window_starts:
        print(f"  {d}  -> EPSS={s:.9f}")
    print()
    print(result.notes)
