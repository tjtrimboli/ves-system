"""Single CVE scan command"""

import asyncio
import click

from ...processing.processor import VESProcessor
from ..formatters.table import TableFormatter
from ..formatters.json import JSONFormatter


@click.command()
@click.argument('cve_id')
@click.option('--format', type=click.Choice(['json', 'table']), default='table', help='Output format')
@click.option('--output', '-o', help='Output file path')
@click.pass_context
def scan(ctx, cve_id, format, output):
    """Scan a single CVE and calculate VES score
    
    Example:
        ves scan CVE-2021-44228
        ves scan CVE-2021-44228 --format json
        ves scan CVE-2021-44228 --output results.json
    """
    config = ctx.obj['config']
    
    async def process():
        async with VESProcessor(config) as processor:
            click.echo(f"Processing {cve_id}...")
            result = await processor.process_single_cve(cve_id)
            
            if format == 'json':
                output_text = JSONFormatter.format_single(result)
            else:
                output_text = TableFormatter.format_single(result)
            
            if output:
                with open(output, 'w') as f:
                    f.write(output_text)
                click.echo(f"Results saved to {output}")
            else:
                click.echo("\n" + output_text)
    
    asyncio.run(process())
