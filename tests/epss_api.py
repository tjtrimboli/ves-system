#!/usr/bin/env python3
"""
EPSS API Diagnostic Script
Test the EPSS API directly to diagnose issues
"""

import asyncio
import aiohttp
import time
import json
from datetime import datetime

async def test_epss_api():
    """Test EPSS API with different methods"""
    
    test_cve = "CVE-2021-44228"  # Known CVE for testing
    base_url = "https://api.first.org/data/v1/epss"
    
    print("🔍 EPSS API Diagnostic Test")
    print("=" * 50)
    
    async with aiohttp.ClientSession() as session:
        
        # Test 1: Current EPSS score
        print(f"\n1️⃣ Testing current EPSS score for {test_cve}")
        url1 = f"{base_url}?cve={test_cve}"
        print(f"URL: {url1}")
        
        start_time = time.time()
        try:
            async with session.get(url1, timeout=aiohttp.ClientTimeout(total=10)) as response:
                duration = time.time() - start_time
                print(f"Status: {response.status}")
                print(f"Duration: {duration:.2f} seconds")
                
                if response.status == 200:
                    data = await response.json()
                    print("✅ SUCCESS")
                    if data.get('data'):
                        cve_data = data['data'][0]
                        print(f"EPSS Score: {cve_data.get('epss')}")
                        print(f"Percentile: {cve_data.get('percentile')}")
                        print(f"Date: {cve_data.get('date')}")
                    else:
                        print("⚠️  No data in response")
                        print(json.dumps(data, indent=2))
                else:
                    error_text = await response.text()
                    print(f"❌ FAILED: {error_text}")
        except Exception as e:
            print(f"❌ ERROR: {e}")
        
        # Test 2: Time-series data (past 30 days)
        print(f"\n2️⃣ Testing time-series EPSS data for {test_cve}")
        url2 = f"{base_url}?cve={test_cve}&scope=time-series"
        print(f"URL: {url2}")
        
        await asyncio.sleep(3)  # Rate limiting
        start_time = time.time()
        try:
            async with session.get(url2, timeout=aiohttp.ClientTimeout(total=15)) as response:
                duration = time.time() - start_time
                print(f"Status: {response.status}")
                print(f"Duration: {duration:.2f} seconds")
                
                if response.status == 200:
                    data = await response.json()
                    print("✅ SUCCESS")
                    time_series = data.get('data', [])
                    print(f"Time-series data points: {len(time_series)}")
                    
                    if time_series:
                        print("Sample data points:")
                        for i, point in enumerate(time_series[:3]):  # Show first 3
                            print(f"  {i+1}. Date: {point.get('date')}, EPSS: {point.get('epss')}")
                        if len(time_series) > 3:
                            print(f"  ... and {len(time_series) - 3} more")
                    else:
                        print("⚠️  No time-series data in response")
                        print(json.dumps(data, indent=2))
                else:
                    error_text = await response.text()
                    print(f"❌ FAILED: {error_text}")
        except Exception as e:
            print(f"❌ ERROR: {e}")
        
        # Test 3: Historical data with specific date
        print(f"\n3️⃣ Testing historical EPSS data for {test_cve}")
        historical_date = "2022-01-01"
        url3 = f"{base_url}?cve={test_cve}&date={historical_date}"
        print(f"URL: {url3}")
        
        await asyncio.sleep(3)  # Rate limiting
        start_time = time.time()
        try:
            async with session.get(url3, timeout=aiohttp.ClientTimeout(total=10)) as response:
                duration = time.time() - start_time
                print(f"Status: {response.status}")
                print(f"Duration: {duration:.2f} seconds")
                
                if response.status == 200:
                    data = await response.json()
                    print("✅ SUCCESS")
                    if data.get('data'):
                        historical_data = data['data'][0]
                        print(f"Historical EPSS ({historical_date}): {historical_data.get('epss')}")
                        print(f"Percentile: {historical_data.get('percentile')}")
                    else:
                        print("⚠️  No historical data found")
                        print(json.dumps(data, indent=2))
                else:
                    error_text = await response.text()
                    print(f"❌ FAILED: {error_text}")
        except Exception as e:
            print(f"❌ ERROR: {e}")
        
        # Test 4: Test with a recent CVE
        print(f"\n4️⃣ Testing with recent CVE (should have less historical data)")
        recent_cve = "CVE-2025-3102"
        url4 = f"{base_url}?cve={recent_cve}&scope=time-series"
        print(f"URL: {url4}")
        
        await asyncio.sleep(3)  # Rate limiting
        start_time = time.time()
        try:
            async with session.get(url4, timeout=aiohttp.ClientTimeout(total=10)) as response:
                duration = time.time() - start_time
                print(f"Status: {response.status}")
                print(f"Duration: {duration:.2f} seconds")
                
                if response.status == 200:
                    data = await response.json()
                    print("✅ SUCCESS")
                    time_series = data.get('data', [])
                    print(f"Time-series data points for recent CVE: {len(time_series)}")
                    
                    if time_series:
                        latest = time_series[0]
                        print(f"Latest: Date: {latest.get('date')}, EPSS: {latest.get('epss')}")
                else:
                    error_text = await response.text()
                    print(f"❌ FAILED: {error_text}")
        except Exception as e:
            print(f"❌ ERROR: {e}")
    
    print("\n" + "=" * 50)
    print("🔍 Diagnostic complete!")
    print("\n💡 If tests 1 and 4 work but test 2 hangs, the issue is with time-series API")
    print("💡 If all tests work, the issue is in our LEV calculation logic")
    print("💡 If tests fail, there might be network/API access issues")

if __name__ == "__main__":
    asyncio.run(test_epss_api())
