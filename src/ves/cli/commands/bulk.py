"""Bulk CVE processing command"""

import asyncio
import csv
import json
import sys
from pathlib import Path
from dataclasses import asdict

import click

from ...processing.processor import VESProcessor
from ...core.models import Severity
from ..formatters.json import JSONFormatter
from ..formatters.csv import CSVFormatter


@click.command()
@click.option('--file', '-f', required=True, help='File containing CVE IDs (one per line)')
@click.option('--output', '-o', help='Output file path')
@click.option('--format', type=click.Choice(['json', 'csv']), default='json', help='Output format')
@click.option('--batch-size', default=50, help='Number of CVEs to process in parallel')
@click.pass_context
def bulk(ctx, file, output, format, batch_size):
    """Process multiple CVEs from a file
    
    Example:
        ves bulk --file cve_list.txt --output results.json
        ves bulk --file cve_list.txt --format csv --output results.csv
    """
    config = ctx.obj['config']
    config.max_concurrent_requests = min(batch_size, config.max_concurrent_requests)
    
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
    
    click.echo(f"Processing {len(cve_ids)} CVEs from {file}...")
    
    async def process():
        async with VESProcessor(config) as processor:
            # Process in batches to manage memory and rate limits
            all_results = []
            
            for i in range(0, len(cve_ids), batch_size):
                batch = cve_ids[i:i + batch_size]
                batch_num = i//batch_size + 1
                total_batches = (len(cve_ids)-1)//batch_size + 1
                
                click.echo(f"Processing batch {batch_num}/{total_batches} ({len(batch)} CVEs)...")
                
                results = await processor.process_bulk_cves(batch)
                all_results.extend(results)
                
                # Show progress
                processed_count = len(all_results)
                click.echo(f"  ✓ Completed batch {batch_num} - Total processed: {processed_count}")
                
                # Brief pause between batches
                if i + batch_size < len(cve_ids):
                    await asyncio.sleep(2)
            
            # Format and save results
            if format == 'csv':
                CSVFormatter.save_bulk(all_results, output)
            else:  # JSON format
                JSONFormatter.save_bulk(all_results, output)
            
            # Summary statistics
            _display_summary(all_results, len(cve_ids))
    
    asyncio.run(process())


def _display_summary(results, total_requested):
    """Display processing summary statistics"""
    click.echo(f"\n{'='*60}")
    click.echo(f"BULK PROCESSING SUMMARY")
    click.echo(f"{'='*60}")
    click.echo(f"Total CVEs requested: {total_requested}")
    click.echo(f"Successfully processed: {len(results)}")
    
    if results:
        kev_count = sum(1 for r in results if r.kev_status)
        critical_count = sum(1 for r in results if r.severity == Severity.CRITICAL)
        high_count = sum(1 for r in results if r.severity == Severity.HIGH)
        priority_1 = sum(1 for r in results if r.priority_level == 1)
        priority_2 = sum(1 for r in results if r.priority_level == 2)
        
        click.echo(f"\n📊 RISK BREAKDOWN:")
        click.echo(f"   🚨 KEV vulnerabilities: {kev_count}")
        click.echo(f"   🔴 Critical severity: {critical_count}")
        click.echo(f"   🟠 High severity: {high_count}")
        click.echo(f"   ⚡ Priority 1 (Urgent): {priority_1}")
        click.echo(f"   🔥 Priority 2 (High): {priority_2}")
        
        valid_ves_scores = [r.ves_score for r in results if r.ves_score is not None]
        if valid_ves_scores:
            avg_ves = sum(valid_ves_scores) / len(valid_ves_scores)
            max_ves = max(valid_ves_scores)
            click.echo(f"\n📈 VES SCORE ANALYSIS:")
            click.echo(f"   Average VES score: {avg_ves:.4f}")
            click.echo(f"   Highest VES score: {max_ves:.4f}")
        
        # Top 5 highest risk CVEs
        sorted_results = sorted(results, key=lambda x: (x.ves_score or 0), reverse=True)
        top_5 = sorted_results[:5]
        
        click.echo(f"\n🎯 TOP 5 HIGHEST RISK:")
        for i, cve in enumerate(top_5, 1):
            status = "🚨 KEV" if cve.kev_status else f"{cve.severity.value}"
            click.echo(f"   {i}. {cve.cve_id} - VES: {cve.ves_score:.4f} ({status})")
