#!/usr/bin/env python3
"""
EPSS API Diagnostic Tool - Debug LEV calculation issues
"""

import asyncio
import aiohttp
import time
import json
from datetime import datetime

async def diagnose_epss_issue():
    """Comprehensive EPSS API diagnostic"""
    
    test_cve = "CVE-2025-3102"  # The CVE that's causing issues
    base_url = "https://api.first.org/data/v1/epss"
    
    print("🔍 EPSS API DIAGNOSTIC - LEV Calculation Issue")
    print("=" * 60)
    print(f"🎯 Testing with: {test_cve}")
    print(f"🌐 EPSS API Base: {base_url}")
    
    # Test with different timeout configurations
    timeout_configs = [
        ("Short", aiohttp.ClientTimeout(total=10, connect=5)),
        ("Medium", aiohttp.ClientTimeout(total=30, connect=10)),
        ("Long", aiohttp.ClientTimeout(total=60, connect=15))
    ]
    
    for timeout_name, timeout_config in timeout_configs:
        print(f"\n🔧 Testing with {timeout_name} timeout ({timeout_config.total}s total)")
        
        async with aiohttp.ClientSession(timeout=timeout_config) as session:
            
            # Test 1: Current EPSS score (should work)
            print(f"\n1️⃣ Testing current EPSS score...")
            url = f"{base_url}?cve={test_cve}"
            
            start_time = time.time()
            try:
                async with session.get(url) as response:
                    duration = time.time() - start_time
                    print(f"   ✅ Current EPSS: {response.status} in {duration:.1f}s")
                    
                    if response.status == 200:
                        data = await response.json()
                        if data.get('data'):
                            epss_score = data['data'][0].get('epss')
                            percentile = data['data'][0].get('percentile')
                            print(f"   📊 Score: {epss_score} ({percentile}%)")
                        else:
                            print(f"   ⚠️  No data in response")
                    else:
                        error_text = await response.text()
                        print(f"   ❌ Error: {error_text[:100]}")
                        
            except asyncio.TimeoutError:
                duration = time.time() - start_time
                print(f"   ⏰ TIMEOUT after {duration:.1f}s")
            except Exception as e:
                duration = time.time() - start_time
                print(f"   💥 ERROR after {duration:.1f}s: {e}")
            
            # Test 2: Time-series data (this is what's hanging)
            print(f"\n2️⃣ Testing time-series EPSS data (PROBLEMATIC)...")
            url = f"{base_url}?cve={test_cve}&scope=time-series"
            
            start_time = time.time()
            try:
                print(f"   🔄 Making request to: {url}")
                async with session.get(url) as response:
                    duration = time.time() - start_time
                    print(f"   ✅ Time-series: {response.status} in {duration:.1f}s")
                    
                    if response.status == 200:
                        data = await response.json()
                        time_series = data.get('data', [])
                        print(f"   📈 Data points: {len(time_series)}")
                        
                        if time_series:
                            # Show first and last few points
                            print(f"   📅 Date range: {time_series[-1].get('date')} to {time_series[0].get('date')}")
                            print(f"   📊 Sample scores:")
                            for i, point in enumerate(time_series[:3]):
                                print(f"      {point.get('date')}: {point.get('epss')}")
                            if len(time_series) > 3:
                                print(f"      ... and {len(time_series) - 3} more points")
                    else:
                        error_text = await response.text()
                        print(f"   ❌ Error {response.status}: {error_text[:200]}")
                        
            except asyncio.TimeoutError:
                duration = time.time() - start_time
                print(f"   ⏰ TIME-SERIES TIMEOUT after {duration:.1f}s ⭐ THIS IS THE PROBLEM!")
            except Exception as e:
                duration = time.time() - start_time
                print(f"   💥 TIME-SERIES ERROR after {duration:.1f}s: {e}")
            
            # Small delay between timeout tests
            await asyncio.sleep(2)
    
    print(f"\n" + "=" * 60)
    print("📊 DIAGNOSTIC SUMMARY")
    print("=" * 60)
    
    # Test alternative approaches
    print(f"\n🔧 Testing Alternative Approaches...")
    
    async with aiohttp.ClientSession() as session:
        
        # Alternative 1: Use current EPSS as LEV estimate
        print(f"\n💡 Alternative 1: Use current EPSS as LEV baseline")
        url = f"{base_url}?cve={test_cve}"
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('data'):
                        epss_score = float(data['data'][0].get('epss', 0.0))
                        
                        # Simple LEV approximation
                        cve_age_days = 124  # From the logs
                        age_factor = min(cve_age_days / 365.0, 1.0)  # Max 1 year factor
                        estimated_lev = epss_score * age_factor * 0.5  # Conservative multiplier
                        
                        print(f"   Current EPSS: {epss_score:.6f}")
                        print(f"   Age factor: {age_factor:.3f}")
                        print(f"   Estimated LEV: {estimated_lev:.6f}")
                        print(f"   ✅ This could work as a fallback!")
                        
        except Exception as e:
            print(f"   ❌ Alternative 1 failed: {e}")
        
        # Alternative 2: Skip LEV entirely
        print(f"\n💡 Alternative 2: Calculate VES without LEV")
        cvss_score = 8.1  # From the logs
        epss_score = 0.839660  # From the logs
        
        # VES without LEV (redistribute weights)
        cvss_normalized = cvss_score / 10.0
        ves_without_lev = (0.55 * epss_score) + (0.45 * cvss_normalized)
        print(f"   CVSS (normalized): {cvss_normalized:.3f}")
        print(f"   EPSS: {epss_score:.6f}")
        print(f"   VES without LEV: {ves_without_lev:.6f}")
        print(f"   ✅ This gives a usable score!")
    
    print(f"\n🎯 RECOMMENDATIONS:")
    print(f"1. 🚀 Use --fast or --skip-lev flag for immediate results")
    print(f"2. ⚡ Implement LEV fallback using current EPSS score")
    print(f"3. 🔧 Add shorter timeout for time-series API calls")
    print(f"4. 📊 Consider caching EPSS time-series data locally")
    print(f"5. 🏃 For bulk processing, always skip LEV for speed")
    
    print(f"\n💡 Quick fix: Try running:")
    print(f"   ves scan CVE-2025-3102 --fast")
    print(f"   ves scan CVE-2025-3102 --skip-lev")

if __name__ == "__main__":
    asyncio.run(diagnose_epss_issue())
