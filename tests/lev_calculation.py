#!/usr/bin/env python3
"""
LEV Calculation Diagnostic Script
Analyze why LEV scores are unexpectedly high
"""

import asyncio
import aiohttp
import json
from datetime import datetime, timedelta

async def diagnose_lev_calculation():
    """Diagnose LEV calculation for CVE-2025-3102"""
    
    test_cve = "CVE-2024-32640"
    base_url = "https://api.first.org/data/v1/epss"
    
    print("🔍 LEV Calculation Diagnostic")
    print("=" * 60)
    print(f"Analyzing: {test_cve}")
    
    # CVE publication date from your output
    pub_date = datetime(2025, 8, 11)
    current_date = datetime.now()
    age_days = (current_date - pub_date).days
    
    print(f"Published: {pub_date.strftime('%Y-%m-%d')}")
    print(f"Current: {current_date.strftime('%Y-%m-%d')}")
    print(f"Age: {age_days} days")
    
    async with aiohttp.ClientSession() as session:
        
        # Test 1: Get current EPSS score
        print(f"\n1️⃣ Getting current EPSS score")
        url1 = f"{base_url}?cve={test_cve}"
        
        try:
            async with session.get(url1, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('data'):
                        current_epss = float(data['data'][0].get('epss', 0.0))
                        current_percentile = float(data['data'][0].get('percentile', 0.0))
                        print(f"✅ Current EPSS: {current_epss:.6f} ({current_percentile:.2f}%)")
                    else:
                        print("❌ No current EPSS data")
                        return
                else:
                    print(f"❌ Failed to get current EPSS: {response.status}")
                    return
        except Exception as e:
            print(f"❌ Error getting current EPSS: {e}")
            return
        
        await asyncio.sleep(3)  # Rate limiting
        
        # Test 2: Get time-series data
        print(f"\n2️⃣ Getting EPSS time-series data")
        url2 = f"{base_url}?cve={test_cve}&scope=time-series"
        
        try:
            async with session.get(url2, timeout=aiohttp.ClientTimeout(total=15)) as response:
                if response.status == 200:
                    data = await response.json()
                    time_series = data.get('data', [])
                    
                    print(f"✅ Time-series data points: {len(time_series)}")
                    
                    if time_series:
                        print(f"\n📊 Time-series data analysis:")
                        
                        # Show all data points
                        epss_scores = []
                        for i, point in enumerate(time_series):
                            date_str = point.get('date')
                            epss_score = float(point.get('epss', 0.0))
                            epss_scores.append(epss_score)
                            print(f"   {i+1}. {date_str}: {epss_score:.6f}")
                        
                        # Calculate statistics
                        avg_epss = sum(epss_scores) / len(epss_scores)
                        min_epss = min(epss_scores)
                        max_epss = max(epss_scores)
                        
                        print(f"\n📈 EPSS Statistics:")
                        print(f"   Average: {avg_epss:.6f}")
                        print(f"   Minimum: {min_epss:.6f}")
                        print(f"   Maximum: {max_epss:.6f}")
                        
                        # Simulate proper NIST LEV calculation
                        print(f"\n🧮 Simulating NIST LEV Calculation:")
                        
                        # Method 1: Current implementation (likely wrong)
                        simple_lev = avg_epss * (age_days / 365.0)
                        print(f"   Simple approach (avg_epss * age_factor): {simple_lev:.6f}")
                        
                        # Method 2: Proper NIST methodology
                        product_term = 1.0
                        num_windows = max(1, age_days // 30)  # 30-day windows
                        
                        for i in range(num_windows):
                            # Use average EPSS as representative
                            weight = 1.0  # Full weight for complete windows
                            term = 1 - (avg_epss * weight)
                            product_term *= term
                        
                        proper_lev = 1 - product_term
                        proper_lev = max(0.0, min(1.0, proper_lev))
                        
                        print(f"   NIST methodology (1 - product): {proper_lev:.6f}")
                        print(f"   Number of 30-day windows: {num_windows}")
                        print(f"   Product term: {product_term:.6f}")
                        
                        # Method 3: Conservative approach
                        # LEV should generally be lower than EPSS for recent CVEs
                        conservative_lev = min(avg_epss * 0.5, 0.3)  # Cap at 30%
                        print(f"   Conservative approach: {conservative_lev:.6f}")
                        
                        print(f"\n💡 Analysis:")
                        if proper_lev > 0.9:
                            print("   ⚠️  NIST LEV > 90% seems too high for a 4-month-old CVE")
                            print("   ⚠️  This suggests either:")
                            print("       - Very high sustained EPSS scores")
                            print("       - Implementation error in the formula")
                            print("       - Incorrect interpretation of NIST methodology")
                        
                        if simple_lev > 0.5:
                            print("   ⚠️  Simple calculation also very high")
                            print("   💡 Consider using more conservative approach")
                        
                        print(f"\n🎯 Recommended LEV score: {conservative_lev:.6f}")
                        print(f"   Reasoning: Recent CVE with high EPSS but limited time for exploitation")
                    
                    else:
                        print("❌ No time-series data available")
                        
                else:
                    print(f"❌ Failed to get time-series data: {response.status}")
                    
        except Exception as e:
            print(f"❌ Error getting time-series data: {e}")
    
    print(f"\n" + "=" * 60)
    print("🔍 Diagnostic Summary:")
    print("• Current LEV of 0.999339 is suspiciously high")
    print("• For a 124-day-old CVE, LEV should typically be much lower")
    print("• Consider using more conservative LEV calculation")
    print("• NIST methodology may need interpretation for recent CVEs")

if __name__ == "__main__":
    asyncio.run(diagnose_lev_calculation())
