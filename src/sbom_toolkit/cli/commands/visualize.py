"""
Visualization commands for SBOM toolkit CLI.
"""

import sys
from pathlib import Path

from ...shared.exceptions import SBOMToolkitError
from ...visualization import (
    create_d3_visualization,
    create_unified_visualization,
    get_available_layouts,
)
from ..utils import get_click

click, CLICK_AVAILABLE = get_click()


@click.command()
@click.argument("sbom_path", type=click.Path(exists=True, path_type=Path))
@click.option("--output-dir", "-o", default="out", help="Output directory for visualizations")
@click.option(
    "--layout",
    "-l",
    type=click.Choice(["force-directed", "hierarchical", "circular"]),
    default="force-directed",
    help="Visualization layout type",
)
@click.option("--open-browser", is_flag=True, help="Open visualization in browser after creation")
@click.pass_context
def visualize(ctx, sbom_path, output_dir, layout, open_browser):
    """Create interactive D3.js visualization of SBOM."""
    logger = ctx.obj["logger"]

    try:
        output_dir_path = Path(output_dir)
        output_dir_path.mkdir(parents=True, exist_ok=True)

        # Check if SBOM already contains vulnerability data
        import json

        with open(sbom_path) as f:
            sbom_data = json.load(f)

        # Check if any component has vulnerability data
        has_vulnerability_data = False
        for component in sbom_data.get("components", []):
            if "vulnerabilities" in component and component["vulnerabilities"]:
                has_vulnerability_data = True
                break

        actual_sbom_path = sbom_path
        if not has_vulnerability_data:
            click.echo("🔍 No vulnerability data found, enriching SBOM...")
            from ...pipeline.security.scanning import process_single_sbom

            enriched_output_path = output_dir_path / f"{sbom_path.stem}_enriched.json"
            success = process_single_sbom(sbom_path, enriched_output_path)
            enriched_path = enriched_output_path if success else None

            if enriched_path:
                actual_sbom_path = enriched_path
                click.echo(f"✓ Created enriched SBOM: {enriched_path}")
            else:
                click.echo("⚠ Failed to enrich SBOM, using original data")

        # Generate output file name
        output_path = output_dir_path / f"{actual_sbom_path.stem}_{layout}_visualization.html"

        # Use D3.js visualization system (backward compatibility)
        html_path = create_d3_visualization(
            sbom_path=actual_sbom_path, output_path=output_path, layout_type=layout
        )

        click.echo(f"✓ Visualization created: {html_path}")

        # Open in browser if requested
        if open_browser:
            import webbrowser

            webbrowser.open(f"file://{html_path.absolute()}")
            click.echo("Opened visualization in browser")

        logger.info(f"Visualization created for {sbom_path} at {html_path}")

    except SBOMToolkitError as e:
        logger.error(f"Visualization failed: {e}")
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        click.echo(f"✗ Unexpected error: {e}", err=True)
        sys.exit(1)


@click.command()
@click.argument("sbom_path", type=click.Path(exists=True, path_type=Path))
@click.option("--output-dir", "-o", default="out", help="Output directory for visualizations")
@click.option(
    "--layouts",
    "-l",
    multiple=True,
    type=click.Choice(["force-directed", "hierarchical", "circular"]),
    help="Visualization layout types to include (can specify multiple)",
)
@click.option("--output-name", help="Custom output file name (default: auto-generated)")
@click.option("--open-browser", is_flag=True, help="Open visualization in browser after creation")
@click.pass_context
def unified_viz(ctx, sbom_path, output_dir, layouts, output_name, open_browser):
    """Create unified interactive visualization with multiple layout options."""
    logger = ctx.obj["logger"]

    try:
        output_dir_path = Path(output_dir)
        output_dir_path.mkdir(parents=True, exist_ok=True)

        # If no layouts specified, use all available
        if not layouts:
            layouts = get_available_layouts()
            click.echo(f"📊 No layouts specified, using all available: {', '.join(layouts)}")
        else:
            layouts = list(layouts)
            click.echo(f"📊 Creating visualization with layouts: {', '.join(layouts)}")

        # Check if SBOM already contains vulnerability data
        import json

        with open(sbom_path) as f:
            sbom_data = json.load(f)

        # Check if any component has vulnerability data
        has_vulnerability_data = False
        for component in sbom_data.get("components", []):
            if "vulnerabilities" in component and component["vulnerabilities"]:
                has_vulnerability_data = True
                break

        actual_sbom_path = sbom_path
        if not has_vulnerability_data:
            click.echo("🔍 No vulnerability data found, enriching SBOM...")
            from ...pipeline.security.scanning import process_single_sbom

            enriched_output_path = output_dir_path / f"{sbom_path.stem}_enriched.json"
            success = process_single_sbom(sbom_path, enriched_output_path)
            enriched_path = enriched_output_path if success else None

            if enriched_path:
                actual_sbom_path = enriched_path
                click.echo(f"✓ Created enriched SBOM: {enriched_path}")
            else:
                click.echo("⚠ Failed to enrich SBOM, using original data")

        # Generate output file name
        if output_name:
            if not output_name.endswith(".html"):
                output_name += ".html"
            output_path = output_dir_path / output_name
        else:
            output_path = output_dir_path / f"{actual_sbom_path.stem}_unified_visualization.html"

        # Create unified visualization
        html_path = create_unified_visualization(
            sbom_path=actual_sbom_path, output_path=output_path, layout_types=layouts
        )

        click.echo(f"✓ Unified visualization created: {html_path}")
        click.echo(f"   Available layouts: {', '.join(layouts)}")

        # Open in browser if requested
        if open_browser:
            import webbrowser

            webbrowser.open(f"file://{html_path.absolute()}")
            click.echo("📱 Opened visualization in browser")

        logger.info(f"Unified visualization created for {sbom_path} at {html_path}")

    except SBOMToolkitError as e:
        logger.error(f"Unified visualization failed: {e}")
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        click.echo(f"✗ Unexpected error: {e}", err=True)
        sys.exit(1)
