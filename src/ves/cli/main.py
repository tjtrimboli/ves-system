"""VES CLI Main Entry Point"""

import asyncio
import logging
import sys
from pathlib import Path

import click

from ..config.settings import VESConfig
from .commands.scan import scan
from .commands.bulk import bulk
from .commands.info import info
from .commands.config import config_cmd
from .commands.version import version


def setup_logging(level: str):
    """Setup logging configuration"""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


@click.group()
@click.option('--log-level', default='INFO', help='Logging level')
@click.option('--config-file', help='Configuration file path')
@click.pass_context
def cli(ctx, log_level, config_file):
    """Vulnerability Evaluation System (VES) CLI
    
    A comprehensive vulnerability assessment tool that combines CVSS, KEV, EPSS, 
    and NIST LEV metrics into a unified VES score for prioritizing security efforts.
    """
    setup_logging(log_level)
    
    if config_file and Path(config_file).exists():
        # TODO: Implement config file loading
        config = VESConfig.from_env()
    else:
        config = VESConfig.from_env()
    
    config.log_level = log_level
    ctx.ensure_object(dict)
    ctx.obj['config'] = config


# Register commands
cli.add_command(scan)
cli.add_command(bulk)
cli.add_command(info)
cli.add_command(config_cmd, name='config')
cli.add_command(version)


if __name__ == '__main__':
    cli()
