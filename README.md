# ServiceNow SecOps MCP Server

An [Arcade](https://docs.arcade.dev/en/home) MCP server for **ServiceNow Security Incident Response (SIR)**. It lets an AI agent finish working a security incident: read it, record its classification and verdict, tag it, and move it to the next state.

It runs as a **dedicated ServiceNow service account**, not as whichever person signed in.

> **Status: scaffold.** The tools run against a mocked ServiceNow but have not been tested against a live SIR instance. Several table and field names are unverified; see [Verify the SIR schema](#verify-the-sir-schema-before-first-use).

## Contents

- [Tools](#tools)
- [How authentication works](#how-authentication-works)
- [Set up ServiceNow](#set-up-servicenow)
- [Run locally](#run-locally)
- [Deploy to Arcade](#deploy-to-arcade)
- [Verify the SIR schema before first use](#verify-the-sir-schema-before-first-use)
- [Project layout](#project-layout)
- [Development](#development)
- [Arcade documentation](#arcade-documentation)

## Tools

| Tool | What it does |
|---|---|
| `GetSecurityIncident` | Reads a security incident by number (`SIR0010001`) or sys_id. Returns each field with both its stored value and display label, plus the incident's security tags and secure notes. |
| `ListSecurityIncidentFieldChoices` | Lists the valid values for `state`, `category`, `subcategory` (optionally filtered by category), `business_impact`, or `security_tag`, as configured on your instance. |
| `UpdateSecurityIncident` | Sets state, category, subcategory and business impact, and optionally adds a secure note. Accepts a display label or a stored value, and checks it against the instance's choice list before writing. |
| `AddSecurityTag` | Applies a security tag to an incident by name. Does nothing if the tag is already applied, so it is safe to retry. |

When a value is not valid, the tools return a retryable error that lists the valid options, so the agent can correct itself without a separate lookup.

### Use it alongside the general ServiceNow toolkit

This server only covers SIR-specific work. General ServiceNow work, such as work notes and assignment, is handled by Arcade's [ServiceNow toolkit](https://docs.arcade.dev/en/resources/integrations/customer-support/servicenow). To give an agent both, add both servers' tools to one [MCP Gateway](https://docs.arcade.dev/en/operate/governance/mcp-gateways/create-via-dashboard).

## How authentication works

Arcade's OAuth providers use the authorization-code flow, so a connection acts as the person who signed in. Security operations teams often want the agent to act as a **service account** instead, so every change it makes is clearly attributable to the agent in ServiceNow.

This server does that with the **OAuth client-credentials grant**:

1. The server reads three [Arcade secrets](https://docs.arcade.dev/en/build/create-tools/tool-basics/create-tool-secrets): `SERVICENOW_INSTANCE_URL`, `SERVICENOW_CLIENT_ID`, and `SERVICENOW_CLIENT_SECRET`.
2. It exchanges the client ID and secret for an access token at `https://<instance>.service-now.com/oauth_token.do`.
3. It caches the token in memory until shortly before it expires. If ServiceNow rejects a token, the cache entry is dropped and the next call gets a new one.

The values are never in the code. Tools declare the secret *names* they need with `requires_secrets`, and Arcade supplies the values at run time. The model and the MCP client never see them.

**Trade-off:** in ServiceNow, every change shows as the service account. Arcade's own logs still record which user and agent called each tool.

## Set up ServiceNow

You need a ServiceNow admin for these steps. The exact menus depend on your ServiceNow release.

1. **Create the service account.** Create a ServiceNow user for the agent and give it the Security Incident Response roles it needs to read and update security incidents, manage security tags, and read and write secure notes. Grant only what the agent needs.
2. **Create an OAuth client for it.** In Machine Identity Console (Zurich and later) or Application Registry (earlier releases), create an OAuth API endpoint for external clients. Enable the **client credentials** grant and set the service account as its **OAuth Application User**. Client credentials requires a ServiceNow release that supports it; check your instance's documentation.
3. **Copy the client ID and client secret.** You will store them in Arcade, not in this repository.

## Run locally

Requirements: Python 3.10+ and [uv](https://docs.astral.sh/uv/).

1. Install the [Arcade CLI](https://docs.arcade.dev/en/references/arcade-cli) and log in:

   ```bash
   uv tool install arcade-mcp
   arcade login
   ```

2. Install dependencies:

   ```bash
   uv sync --extra dev
   ```

3. Create a local `.env` from the example and fill in a **development** instance's values. `.env` is ignored by git; never commit it.

   ```bash
   cp .env.example .env
   ```

4. Start the server. The default `stdio` transport supports secrets locally:

   ```bash
   uv run src/servicenow_secops/server.py
   ```

   Pass `http` to serve over HTTP instead. Tools that need secrets will only run over HTTP once the server is deployed to Arcade; see [Compare MCP server types](https://docs.arcade.dev/en/build/create-tools/tool-basics/compare-server-types).

5. Connect a client. `arcade configure` can set up Claude Desktop, Cursor, or VS Code; see the [CLI reference](https://docs.arcade.dev/en/references/arcade-cli).

## Deploy to Arcade

[`arcade deploy`](https://docs.arcade.dev/en/build/arcade-deploy) packages this server, registers it with Arcade, and adds its tools to your project's catalog.

1. **Store the secrets in Arcade first.** Use the Arcade Dashboard (**Secrets**), or the CLI:

   ```bash
   arcade secret set SERVICENOW_INSTANCE_URL=acme.service-now.com SERVICENOW_CLIENT_ID=... SERVICENOW_CLIENT_SECRET=...
   ```

   For a production instance, have whoever owns the ServiceNow credentials enter them directly in the Dashboard, so the client secret is never handled by anyone else.

2. **Deploy** from the repository root (where `pyproject.toml` is):

   ```bash
   arcade deploy -e src/servicenow_secops/server.py --secrets skip
   ```

   `--secrets skip` keeps the values already stored in Arcade. The default (`auto`) upserts the server's required secrets during deploy, which can overwrite production values with whatever is in your local environment or `.env`. See the [`arcade deploy` docs](https://docs.arcade.dev/en/build/arcade-deploy) for every option.

3. **Expose the tools** through an [MCP Gateway](https://docs.arcade.dev/en/operate/governance/mcp-gateways/create-via-dashboard), together with the ServiceNow toolkit if the agent needs both.

## Verify the SIR schema before first use

SIR table and field names vary between plugin versions. The names below are in [`constants.py`](src/servicenow_secops/constants.py) and are marked `UNVERIFIED`. Confirm each one on your instance (`sys_db_object` for tables, `sys_dictionary` for fields) and update the constants if they differ.

| Constant | Current value | What it should be |
|---|---|---|
| `SECURITY_TAG_TABLE` | `sn_sec_cmn_security_tag` | Table holding security tag definitions |
| `SIR_TAG_M2M_TABLE` | `sn_sec_cmn_m2m_security_tag` | Table linking tags to security incidents |
| `SIR_TAG_M2M_RECORD_FIELD` | `record` | Field on the link table that references the incident |
| `SIR_TAG_M2M_TAG_FIELD` | `security_tag` | Field on the link table that references the tag |
| `SECURE_NOTES_FIELD` | `secure_notes` | Journal field for secure notes |
| `UPDATABLE_CHOICE_FIELDS["business_impact"]` | `business_criticality` | Field behind "Business impact" |
| `"company"` in `SIR_FIELDS` | `company` | Field behind "Organization" |

### Known gaps

- Organization is read but cannot be set yet, because it is a reference field.
- When only `subcategory` is passed to `UpdateSecurityIncident`, it is not checked against the incident's current category.
- No automated tests or [evals](https://docs.arcade.dev/en/build/create-tools/evaluate-tools) yet.

## Project layout

```
src/servicenow_secops/
├── server.py      # MCPApp entry point; registers the tools
├── tools.py       # The four tools
├── sir.py         # Incident lookup, choice lists, and tag helpers
├── client.py      # ServiceNow REST calls and error mapping
├── auth.py        # Client-credentials token minting and caching
└── constants.py   # Table and field names (see "Verify the SIR schema")
```

## Development

```bash
uv sync --extra dev
uv run ruff check src
uv run ruff format src
uv run mypy src
```

Tools use the `@tool` decorator from `arcade-mcp-server`, with [tool metadata](https://docs.arcade.dev/en/build/create-tools/tool-basics/add-tool-metadata) describing their behavior and [typed errors](https://docs.arcade.dev/en/build/create-tools/error-handling/useful-tool-errors) that tell the model how to recover.

## Arcade documentation

- [Arcade docs home](https://docs.arcade.dev/en/home)
- [Arcade CLI reference](https://docs.arcade.dev/en/references/arcade-cli)
- [Deploy with `arcade deploy`](https://docs.arcade.dev/en/build/arcade-deploy)
- [Tool secrets](https://docs.arcade.dev/en/build/create-tools/tool-basics/create-tool-secrets)
- [Compare MCP server types (stdio, HTTP, deployed)](https://docs.arcade.dev/en/build/create-tools/tool-basics/compare-server-types)
- [Create an MCP Gateway](https://docs.arcade.dev/en/operate/governance/mcp-gateways/create-via-dashboard)
- [ServiceNow toolkit](https://docs.arcade.dev/en/resources/integrations/customer-support/servicenow)
- [ServiceNow auth provider](https://docs.arcade.dev/en/references/auth-providers/servicenow)
- [Tool metadata](https://docs.arcade.dev/en/build/create-tools/tool-basics/add-tool-metadata)
- [Useful tool errors](https://docs.arcade.dev/en/build/create-tools/error-handling/useful-tool-errors)
- [Evaluate tools](https://docs.arcade.dev/en/build/create-tools/evaluate-tools)
