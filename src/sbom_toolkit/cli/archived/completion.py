"""
Shell completion installation commands for the SBOM toolkit.
"""

import os
import sys
from pathlib import Path

from ..utils import get_click

click, _ = get_click()


def get_shell_config_file() -> Path | None:
    """Detect and return the appropriate shell configuration file."""
    shell = os.environ.get("SHELL", "").split("/")[-1]
    home = Path.home()

    if shell == "zsh":
        # Check for .zshrc
        zshrc = home / ".zshrc"
        if zshrc.exists():
            return zshrc
        # Fallback to creating .zshrc
        return zshrc
    elif shell == "bash":
        # Check for .bashrc first, then .bash_profile
        bashrc = home / ".bashrc"
        if bashrc.exists():
            return bashrc
        bash_profile = home / ".bash_profile"
        if bash_profile.exists():
            return bash_profile
        # Fallback to .bashrc
        return bashrc
    elif shell == "fish":
        # Fish completions go in a specific directory
        fish_config_dir = home / ".config" / "fish" / "completions"
        fish_config_dir.mkdir(parents=True, exist_ok=True)
        return fish_config_dir / "sbom.fish"

    return None


def get_completion_command(shell: str) -> str:
    """Get the completion command for the specified shell."""
    if shell == "zsh":
        return '# SBOM toolkit completion (only load if command exists)\nif command -v sbom >/dev/null 2>&1; then\n    eval "$(_SBOM_COMPLETE=zsh_source sbom)"\nfi'
    elif shell == "bash":
        return '# SBOM toolkit completion (only load if command exists)\nif command -v sbom >/dev/null 2>&1; then\n    eval "$(_SBOM_COMPLETE=bash_source sbom)"\nfi'
    elif shell == "fish":
        return (
            "if command -v sbom >/dev/null 2>&1\n    _SBOM_COMPLETE=fish_source sbom | source\nend"
        )
    else:
        raise ValueError(f"Unsupported shell: {shell}")


@click.group()
def completion():
    """Manage shell completions for the SBOM toolkit."""
    pass


@completion.command("install")
@click.option(
    "--shell",
    type=click.Choice(["zsh", "bash", "fish"]),
    help="Shell to install completions for (auto-detected if not specified)",
)
@click.option("--force", is_flag=True, help="Overwrite existing completion configuration")
def install_completion(shell: str | None, force: bool):
    """Install shell completions for the SBOM toolkit."""
    # Auto-detect shell if not specified
    if shell is None:
        detected_shell = os.environ.get("SHELL", "").split("/")[-1]
        if detected_shell not in ["zsh", "bash", "fish"]:
            click.echo("Error: Could not auto-detect shell. Please specify --shell", err=True)
            sys.exit(1)
        shell = detected_shell

    config_file = get_shell_config_file()
    if config_file is None:
        click.echo(f"Error: Could not determine config file for {shell}", err=True)
        sys.exit(1)

    # At this point, config_file is guaranteed to be a Path
    assert config_file is not None
    completion_command = get_completion_command(shell)

    # Check if completion is already installed
    if config_file.exists():
        content = config_file.read_text()
        if "_SBOM_COMPLETE" in content and not force:
            click.echo(f"SBOM completions already installed in {config_file}")
            click.echo("Use --force to reinstall")
            return

    # For fish, write the completion directly
    if shell == "fish":
        try:
            # Generate fish completion script
            import subprocess

            result = subprocess.run(
                ["sbom"],
                env={**os.environ, "_SBOM_COMPLETE": "fish_source"},
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                config_file.write_text(result.stdout)
                click.echo(f"Fish completions installed to {config_file}")
            else:
                click.echo(f"Error generating fish completions: {result.stderr}", err=True)
                sys.exit(1)
        except Exception as e:
            click.echo(f"Error installing fish completions: {e}", err=True)
            sys.exit(1)
    else:
        # For zsh/bash, append to config file
        try:
            with config_file.open("a") as f:
                f.write(f"\n{completion_command}\n")
            click.echo(f"Completions installed to {config_file}")
            click.echo(f"Restart your shell or run: source {config_file}")
        except Exception as e:
            click.echo(f"Error writing to {config_file}: {e}", err=True)
            sys.exit(1)


@completion.command("uninstall")
@click.option(
    "--shell",
    type=click.Choice(["zsh", "bash", "fish"]),
    help="Shell to uninstall completions from (auto-detected if not specified)",
)
def uninstall_completion(shell: str | None):
    """Uninstall shell completions for the SBOM toolkit."""
    # Auto-detect shell if not specified
    if shell is None:
        detected_shell = os.environ.get("SHELL", "").split("/")[-1]
        if detected_shell not in ["zsh", "bash", "fish"]:
            click.echo("Error: Could not auto-detect shell. Please specify --shell", err=True)
            sys.exit(1)
        shell = detected_shell

    config_file = get_shell_config_file()
    if config_file is None or not config_file.exists():
        click.echo(f"No config file found for {shell}")
        return

    if shell == "fish":
        # For fish, just remove the completion file
        if config_file.exists():
            config_file.unlink()
            click.echo(f"Fish completions removed from {config_file}")
        else:
            click.echo("No fish completions found")
    else:
        # For zsh/bash, remove lines from config file
        try:
            lines = config_file.read_text().splitlines()
            new_lines = []
            skip_next = False

            for line in lines:
                if skip_next and "_SBOM_COMPLETE" in line:
                    skip_next = False
                    continue
                elif "# SBOM toolkit completion" in line:
                    skip_next = True
                    continue
                elif "_SBOM_COMPLETE" in line and "sbom" in line:
                    continue
                else:
                    new_lines.append(line)

            config_file.write_text("\n".join(new_lines) + "\n")
            click.echo(f"Completions removed from {config_file}")
            click.echo(f"Restart your shell or run: source {config_file}")
        except Exception as e:
            click.echo(f"Error modifying {config_file}: {e}", err=True)
            sys.exit(1)


@completion.command("show")
@click.option(
    "--shell",
    type=click.Choice(["zsh", "bash", "fish"]),
    help="Shell to show completion command for (auto-detected if not specified)",
)
def show_completion(shell: str | None):
    """Show the completion command for manual installation."""
    # Auto-detect shell if not specified
    if shell is None:
        detected_shell = os.environ.get("SHELL", "").split("/")[-1]
        if detected_shell not in ["zsh", "bash", "fish"]:
            click.echo("Error: Could not auto-detect shell. Please specify --shell", err=True)
            sys.exit(1)
        shell = detected_shell

    try:
        completion_command = get_completion_command(shell)
        config_file = get_shell_config_file()

        click.echo(f"Shell: {shell}")
        click.echo(f"Completion command: {completion_command}")
        if config_file:
            click.echo(f"Config file: {config_file}")
        click.echo("--------------------------------")
        click.echo(f"To manually install, add this line to your {shell} config:")
        click.echo(completion_command)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@completion.command("status")
def completion_status():
    """Check if completions are installed."""
    shell = os.environ.get("SHELL", "").split("/")[-1]
    if shell not in ["zsh", "bash", "fish"]:
        click.echo(f"Unsupported shell: {shell}")
        return

    config_file = get_shell_config_file()
    if config_file is None:
        click.echo(f"Could not determine config file for {shell}")
        return

    if not config_file.exists():
        click.echo(f"Config file {config_file} does not exist")
        return

    if shell == "fish":
        installed = config_file.exists()
    else:
        content = config_file.read_text()
        installed = "_SBOM_COMPLETE" in content and "sbom" in content

    click.echo(f"Shell: {shell}")
    click.echo(f"Config file: {config_file}")
    click.echo(f"Completions installed: {'Yes' if installed else 'No'}")
