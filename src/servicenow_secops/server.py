#!/usr/bin/env python3
"""ServiceNow Security Incident Response (SIR) MCP server.

Complements the shared ServiceNow toolkit with SIR-specific tools, and runs as a
dedicated ServiceNow service account (see auth.py) instead of the signed-in user.
"""

import sys
from typing import Literal

from arcade_mcp_server import MCPApp

import servicenow_secops

app = MCPApp(name="ServiceNowSecOps", version="0.2.0", log_level="DEBUG")

app.add_tools_from_module(servicenow_secops)

if __name__ == "__main__":
    # "stdio" (default) supports secrets locally; "http" needs `arcade deploy` (or the
    # Dashboard's "Arcade" server type) before tools that require secrets will run.
    transport: Literal["http", "stdio"] = "http" if sys.argv[1:2] == ["http"] else "stdio"
    app.run(transport=transport, host="127.0.0.1", port=8000)
