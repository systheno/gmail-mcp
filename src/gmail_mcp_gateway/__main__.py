"""Allow ``python -m gmail_mcp_gateway``."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
