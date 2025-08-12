"""Bulk CVE processing command"""

import asyncio
import csv
import json
import sys
from pathlib import Path
from dataclasses import asdict

import click

from ...processing.processor import VESProcessor
from ...core.models import Severity, VulnerabilityMetrics
from ..formatters.json import JSONFormatter
from ..formatters.csv import CSVFormatter


@click.command()
@click.option('--file', '-f', required=True, help='File containing CVE IDs (one per line)')
@click.option('--output', '-o', help='Output file path')
@click.option('--format', type=click.Choice(['json', 'csv']), default='json', help='Output format')
@click.option('--batch-size', default=50, help='Number of CVEs to process in parallel')
@click.option('--skip-lev', is_flag=True, help='Skip LEV calculation for faster processing')
@click.option('--fast', is_flag=True, help='Use fast mode (skips LEV, reduced timeouts)')
@click.option('--debug', is_flag=True, help='Enable debug logging')
@click.pass_context
def bulk(ctx, file, output, format, batch_size, skip_lev, fast, debug):
    """Process multiple CVEs from a file
    
    Examples:
        ves bulk --file cve_list.txt                           # Full analysis
        ves bulk --file cve_list.txt --fast                    # Fast mode (no LEV)
        ves bulk --file cve_list.txt --skip-lev                # Skip LEV only
        ves bulk --file cve_list.txt --format csv              # CSV output
        ves bulk --file cve_list.txt --batch-size 25           # Smaller batches
    """
    config = ctx.obj['config']
    
    # Fast mode configuration
    if fast:
        skip_lev = True
        batch_size = min(batch_size, 25)  # Smaller batches in fast mode
        click.echo("🚀 Fast mode enabled - LEV calculation disabled for speed")
    
    # Adjust concurrent requests based on mode
    if skip_lev:
        config.max_concurrent_requests = min(batch_size, config.max_concurrent_requests)
    else:
        # Reduce concurrency when LEV is enabled to prevent timeouts
        config.max_concurrent_requests = min(batch_size // 2, config.max_concurrent_requests)
    
    # Enable debug logging if requested
    if debug:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)
        config.log_level = 'DEBUG'
    
    # Read CVE IDs from file
    try:
        with open(file, 'r') as f:
            cve_ids = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        click.echo(f"Error: File {file} not found", err=True)
        sys.exit(1)
    
    if not cve_ids:
        click.echo("Error: No CVE IDs found in file", err=True)
        sys.exit(1)
    
    # Show processing configuration
    mode_text = "🚀 FAST BULK MODE" if fast else "🔍 FULL BULK ANALYSIS"
    if skip_lev and not fast:
        mode_text += " (LEV disabled)"
    
    click.echo(f"{mode_text}")
    click.echo(f"📋 Processing {len(cve_ids)} CVEs from {file}")
    click.echo(f"⚙️  Batch size: {batch_size}")
    click.echo(f"🔄 Concurrent requests: {config.max_concurrent_requests}")
    
    if skip_lev:
        click.echo("📊 LEV calculation disabled - using CVSS, EPSS, and KEV only")
        estimated_time = len(cve_ids) * 2  # ~2 seconds per CVE without LEV
    else:
        click.echo("📊 Full VES analysis with LEV calculation")
        estimated_time = len(cve_ids) * 8  # ~8 seconds per CVE with LEV
    
    estimated_minutes = estimated_time // 60
    if estimated_minutes > 0:
        click.echo(f"⏱️  Estimated time: ~{estimated_minutes} minutes")
    else:
        click.echo(f"⏱️  Estimated time: ~{estimated_time} seconds")
    
    async def process():
        async with VESProcessor(config) as processor:
            # Process in batches to manage memory and rate limits
            all_results = []
            start_time = asyncio.get_event_loop().time()
            
            for i in range(0, len(cve_ids), batch_size):
                batch = cve_ids[i:i + batch_size]
                batch_num = i//batch_size + 1
                total_batches = (len(cve_ids)-1)//batch_size + 1
                
                batch_start = asyncio.get_event_loop().time()
                click.echo(f"\n🔄 Processing batch {batch_num}/{total_batches} ({len(batch)} CVEs)...")
                
                try:
                    # Set timeout per batch based on mode
                    batch_timeout = 120 if skip_lev else 300  # 2 min fast, 5 min full
                    
                    results = await asyncio.wait_for(
                        processor.process_bulk_cves(batch, skip_lev=skip_lev),
                        timeout=batch_timeout
                    )
                    all_results.extend(results)
                    
                    # Show batch progress
                    batch_time = asyncio.get_event_loop().time() - batch_start
                    processed_count = len(all_results)
                    
                    click.echo(f"  ✅ Batch {batch_num} completed in {batch_time:.1f}s")
                    click.echo(f"  📊 Total processed: {processed_count}/{len(cve_ids)}")
                    
                    # Show progress statistics
                    if results:
                        batch_kev = sum(1 for r in results if r.kev_status)
                        batch_critical = sum(1 for r in results if r.severity == Severity.CRITICAL)
                        if batch_kev > 0 or batch_critical > 0:
                            click.echo(f"  🚨 Batch findings: {batch_kev} KEV, {batch_critical} Critical")
                    
                except asyncio.TimeoutError:
                    click.echo(f"  ⏰ Batch {batch_num} timed out - continuing with next batch")
                    # Create placeholder results for timed out batch
                    failed_results = [VulnerabilityMetrics(cve_id=cve_id) for cve_id in batch]
                    all_results.extend(failed_results)
                except Exception as e:
                    click.echo(f"  💥 Batch {batch_num} failed: {e}")
                    # Create placeholder results for failed batch
                    failed_results = [VulnerabilityMetrics(cve_id=cve_id) for cve_id in batch]
                    all_results.extend(failed_results)
                
                # Brief pause between batches unless in fast mode
                if i + batch_size < len(cve_ids) and not fast:
                    await asyncio.sleep(2)
            
            # Calculate total processing time
            total_time = asyncio.get_event_loop().time() - start_time
            
            # Format and save results
            click.echo(f"\n💾 Saving results...")
            if format == 'csv':
                CSVFormatter.save_bulk(all_results, output)
            else:  # JSON format
                JSONFormatter.save_bulk(all_results, output)
            
            # Enhanced summary statistics
            _display_enhanced_summary(all_results, len(cve_ids), total_time, skip_lev)
    
    asyncio.run(process())


def _display_enhanced_summary(results, total_requested, processing_time, skip_lev):
    """Display comprehensive processing summary statistics"""
    click.echo(f"\n{'='*70}")
    click.echo(f"BULK PROCESSING SUMMARY")
    click.echo(f"{'='*70}")
    
    # Basic stats
    click.echo(f"📋 Processing Results:")
    click.echo(f"   Total CVEs requested: {total_requested}")
    click.echo(f"   Successfully processed: {len(results)}")
    click.echo(f"   Processing time: {processing_time:.1f} seconds")
    
    if results:
        # Risk breakdown
        kev_count = sum(1 for r in results if r.kev_status)
        critical_count = sum(1 for r in results if r.severity == Severity.CRITICAL)
        high_count = sum(1 for r in results if r.severity == Severity.HIGH)
        priority_1 = sum(1 for r in results if r.priority_level == 1)
        priority_2 = sum(1 for r in results if r.priority_level == 2)
        
        click.echo(f"\n🎯 Risk Assessment:")
        click.echo(f"   🚨 KEV (Known Exploited): {kev_count}")
        click.echo(f"   🔴 Critical severity: {critical_count}")
        click.echo(f"   🟠 High severity: {high_count}")
        click.echo(f"   ⚡ Priority 1 (Urgent): {priority_1}")
        click.echo(f"   🔥 Priority 2 (High): {priority_2}")
        
        # VES score analysis
        valid_ves_scores = [r.ves_score for r in results if r.ves_score is not None]
        if valid_ves_scores:
            avg_ves = sum(valid_ves_scores) / len(valid_ves_scores)
            max_ves = max(valid_ves_scores)
            high_risk_count = sum(1 for score in valid_ves_scores if score >= 0.7)
            
            click.echo(f"\n📊 VES Score Analysis:")
            click.echo(f"   Average VES score: {avg_ves:.4f}")
            click.echo(f"   Highest VES score: {max_ves:.4f}")
            click.echo(f"   High risk (≥0.7): {high_risk_count}")
        
        # Data completeness
        cvss_available = sum(1 for r in results if r.cvss_score is not None)
        epss_available = sum(1 for r in results if r.epss_score is not None)
        lev_available = sum(1 for r in results if r.lev_score is not None)
        
        click.echo(f"\n📈 Data Completeness:")
        click.echo(f"   CVSS data: {cvss_available}/{len(results)} ({cvss_available/len(results)*100:.1f}%)")
        click.echo(f"   EPSS data: {epss_available}/{len(results)} ({epss_available/len(results)*100:.1f}%)")
        if not skip_lev:
            click.echo(f"   LEV data: {lev_available}/{len(results)} ({lev_available/len(results)*100:.1f}%)")
        else:
            click.echo(f"   LEV data: Skipped (fast mode)")
        
        # Top 5 highest risk CVEs
        sorted_results = sorted(results, key=lambda x: (x.ves_score or 0), reverse=True)
        top_5 = sorted_results[:5]
        
        click.echo(f"\n🎯 TOP 5 HIGHEST RISK CVEs:")
        for i, cve in enumerate(top_5, 1):
            if cve.ves_score:
                status = "🚨 KEV" if cve.kev_status else f"{cve.severity.value}"
                click.echo(f"   {i}. {cve.cve_id} - VES: {cve.ves_score:.4f} ({status})")
            else:
                click.echo(f"   {i}. {cve.cve_id} - VES: N/A")
        
        # Performance metrics
        avg_time = processing_time / len(results)
        click.echo(f"\n⚡ Performance:")
        click.echo(f"   Average time per CVE: {avg_time:.2f} seconds")
        click.echo(f"   Processing rate: {len(results)/processing_time:.1f} CVEs/second")
        
        # Recommendations
        click.echo(f"\n💡 Recommendations:")
        urgent_count = priority_1 + kev_count
        if urgent_count > 0:
            click.echo(f"   🚨 {urgent_count} CVEs require immediate attention")
        if high_risk_count > 0:
            click.echo(f"   🔥 {high_risk_count} CVEs are high risk (VES ≥ 0.7)")
        if not skip_lev and lev_available < len(results) * 0.8:
            click.echo(f"   📊 Consider using --fast mode for better performance")
    
    click.echo(f"\n✅ Processing complete!")
