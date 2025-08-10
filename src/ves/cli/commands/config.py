"""Configuration management commands"""

import os
import click

from ...config.settings import VESConfig


@click.command('config')
@click.option('--show-env', is_flag=True, help='Show all environment variables')
@click.option('--validate', is_flag=True, help='Validate configuration')
def config_cmd(show_env, validate):
    """Show current VES configuration
    
    Example:
        ves config
        ves config --show-env
        ves config --validate
    """
    config = VESConfig.from_env()
    
    click.echo("🔧 VES SYSTEM CONFIGURATION")
    click.echo("=" * 50)
    
    # Core Configuration
    click.echo(f"\n📡 API Configuration:")
    click.echo(f"   NVD API Key: {'✅ Set' if config.nvd_api_key else '❌ Not Set'}")
    click.echo(f"   Rate Limit Delay: {config.rate_limit_delay}s")
    click.echo(f"   Max Concurrent: {config.max_concurrent_requests}")
    click.echo(f"   Cache TTL: {config.cache_ttl}s")
    click.echo(f"   Log Level: {config.log_level}")
    
    # API Endpoints
    click.echo(f"\n🌐 API Endpoints:")
    click.echo(f"   NVD: {config.nvd_base_url}")
    click.echo(f"   EPSS: {config.epss_base_url}")
    click.echo(f"   KEV: {config.kev_url}")
    
    # Performance Settings
    click.echo(f"\n⚡ Performance Settings:")
    if config.rate_limit_delay < 6.0:
        click.echo(f"   ⚠️  Rate limit delay is below recommended 6.0s")
    if config.max_concurrent_requests > 20:
        click.echo(f"   ⚠️  High concurrency may hit rate limits")
    
    # Environment Variables (if requested)
    if show_env:
        click.echo(f"\n🔐 Environment Variables:")
        env_vars = [
            'NVD_API_KEY',
            'VES_RATE_LIMIT_DELAY', 
            'VES_MAX_CONCURRENT',
            'VES_LOG_LEVEL'
        ]
        
        for var in env_vars:
            value = os.getenv(var)
            if var == 'NVD_API_KEY' and value:
                # Mask the API key
                display_value = f"{value[:8]}..." if len(value) > 8 else "***"
            else:
                display_value = value or "Not Set"
            click.echo(f"   {var}: {display_value}")
    
    # Validation (if requested)
    if validate:
        click.echo(f"\n✅ Configuration Validation:")
        issues = []
        
        if not config.nvd_api_key:
            issues.append("❌ NVD API key not set - will be rate limited to 5 requests/30s")
        
        if config.rate_limit_delay < 6.0 and config.nvd_api_key:
            issues.append("⚠️  Rate limit delay may be too aggressive for NVD API")
        
        if config.max_concurrent_requests > 10 and not config.nvd_api_key:
            issues.append("⚠️  High concurrency without API key will cause failures")
        
        if not issues:
            click.echo("   ✅ Configuration looks good!")
        else:
            click.echo("   Issues found:")
            for issue in issues:
                click.echo(f"      {issue}")
    
    # Quick setup guide
    click.echo(f"\n📋 Quick Setup:")
    click.echo(f"   1. Get NVD API key: https://nvd.nist.gov/developers/request-an-api-key")
    click.echo(f"   2. Set environment: export NVD_API_KEY=your_key_here")
    click.echo(f"   3. Test with: ves scan CVE-2021-44228")
