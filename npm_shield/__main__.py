"""Allow ``python -m npm_shield`` to run the CLI."""

import sys

from npm_shield.cli import main

if __name__ == "__main__":
    sys.exit(main())
