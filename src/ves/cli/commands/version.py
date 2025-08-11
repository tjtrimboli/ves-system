"""Version information command"""

import click
import sys
import platform


@click.command()
def version():
    """Show VES CLI version and system information"""
    click.echo("🚀 VULNERABILITY EVALUATION SYSTEM (VES)")
    click.echo("=" * 50)
    
    click.echo(f"\n📦 Version Information:")
    click.echo(f"   VES CLI Version: 1.0.0")
    click.echo(f"   Phase: 1 - Core Foundation")
    click.echo(f"   Build: Phase1-CLI-Complete")
    
    click.echo(f"\n🔬 Integrated Metrics:")
    click.echo(f"   • CVSS (Common Vulnerability Scoring System)")
    click.echo(f"     └─ Severity assessment from NVD")
    click.echo(f"   • KEV (CISA Known Exploited Vulnerabilities)")
    click.echo(f"     └─ Binary indicator of confirmed exploitation")
    click.echo(f"   • EPSS (Exploit Prediction Scoring System)")
    click.echo(f"     └─ Machine learning-based exploitation probability")
    click.echo(f"   • LEV (NIST Likely Exploited Vulnerabilities)")
    click.echo(f"     └─ Historical exploitation likelihood calculation")
    
    click.echo(f"\n🧮 VES Scoring Algorithm:")
    click.echo(f"   Base Score = (40% × EPSS) + (30% × CVSS) + (30% × LEV)")
    click.echo(f"   Final Score = Base Score × KEV Multiplier (1.5x if exploited)")
    
    click.echo(f"\n🏗️  System Information:")
    click.echo(f"   Python Version: {sys.version.split()[0]}")
    click.echo(f"   Platform: {platform.platform()}")
    click.echo(f"   Architecture: {platform.architecture()[0]}")
    
    # Check dependencies
    try:
        import aiohttp
        import click as click_lib
        import asyncpg
        import tenacity
        
        click.echo(f"\n📚 Dependencies:")
        click.echo(f"   • aiohttp: {aiohttp.__version__}")
        click.echo(f"   • click: {click_lib.__version__}")
        click.echo(f"   • asyncpg: {asyncpg.__version__}")
        click.echo(f"   • tenacity: {tenacity.__version__}")
        
    except ImportError as e:
        click.echo(f"\n❌ Missing dependency: {e}")
    
    click.echo(f"\n🔗 Resources:")
    click.echo(f"   • Documentation: https://docs.ves-security.org")
    click.echo(f"   • GitHub: https://github.com/ves-security/ves-cli")
    click.echo(f"   • NIST LEV Paper: https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.41.pdf")
    click.echo(f"   • FIRST EPSS: https://www.first.org/epss/")
    
    click.echo(f"\n💼 Enterprise Features:")
    click.echo(f"   ✅ Async bulk processing")
    click.echo(f"   ✅ Rate limiting & retry logic")
    click.echo(f"   ✅ Multiple output formats")
    click.echo(f"   ✅ Comprehensive error handling")
    click.echo(f"   ✅ Docker containerization")
    click.echo(f"   🚧 REST API (Phase 2)")
    click.echo(f"   🚧 Web dashboard (Phase 3)")
    click.echo(f"   🚧 ML enhancements (Phase 4)")
