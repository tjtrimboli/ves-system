"""Configuration management commands"""

import os
import click

from ...config.settings import VESConfig


@click.command('config')
@click.option('--show-env', is_flag=True, help='Show all environment variables')
@click.option('--validate', is_flag=True, help='Validate configuration')
@click.option('--env-file', help='Specify custom .env file path')
def config_cmd(show_env, validate, env_file):
    """Show current VES configuration
    
    Example:
        ves config
        ves config --show-env
        ves config --validate
        ves config --env-file /path/to/custom.env
    """
    config = VESConfig.from_env(env_file)
    
    click.echo("🔧 VES SYSTEM CONFIGURATION")
    click.echo("=" * 50)
    
    # Core Configuration
    click.echo(f"\n📡 API Configuration:")
    api_key_status = "✅ Set" if config.nvd_api_key else "❌ Not Set"
    if config.nvd_api_key:
        # Show masked API key
        masked_key = f"{config.nvd_api_key[:8]}..." if len(config.nvd_api_key) > 8 else "***"
        api_key_status += f" ({masked_key})"
    click.echo(f"   NVD API Key: {api_key_status}")
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
            'VES_LOG_LEVEL',
            'VES_NVD_BASE_URL',
            'VES_EPSS_BASE_URL',
            'VES_KEV_URL',
            'VES_CACHE_TTL'
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
        issues = config.validate()
        
        if not issues:
            click.echo("   ✅ Configuration looks good!")
        else:
            click.echo("   Issues found:")
            for issue in issues:
                click.echo(f"      ❌ {issue}")
    
    # Quick setup guide
    click.echo(f"\n📋 Quick Setup:")
    click.echo(f"   1. Get NVD API key: https://nvd.nist.gov/developers/request-an-api-key")
    click.echo(f"   2. Create .env file: echo 'NVD_API_KEY=your_key' > .env")
    click.echo(f"   3. Or set environment: export NVD_API_KEY=your_key_here")
    click.echo(f"   4. Test with: ves scan CVE-2021-44228")
