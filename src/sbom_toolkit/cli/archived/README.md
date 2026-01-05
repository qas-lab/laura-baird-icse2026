# Archived CLI Commands

This directory contains CLI commands that have been moved from active use but preserved for future development or reference.

## Commands

### Validation Commands (`validate.py`)

- **`validate-generation`** - Originally compared Docker-based vs Syft SBOM generation
  - **Status**: Partially broken due to Docker support being archived
  - **Issue**: References `docker_tools.py` functionality that was moved to `pipeline/archived/`
  - **Future Work**: Needs refactoring to compare different generation methods without Docker dependency

- **`validate-visualization`** - Validates SBOM visualization accuracy
  - **Status**: Uses legacy components, may need updating
  - **Future Work**: Update to use new unified visualization system

### Shell Completion (`completion.py`)

- **`completion`** - Shell completion management for bash/zsh/fish
  - **Status**: Functional but not actively maintained
  - **Future Work**: Could be enhanced with more sophisticated completion logic

## Notes

- Commands in this directory are **not actively maintained or tested**
- They are preserved for reference and potential future development
- Do not import these commands into the main CLI without refactoring first
- See the main CLI documentation for current supported commands
