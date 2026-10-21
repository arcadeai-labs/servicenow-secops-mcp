# ServiceNow SecOps MCP Server

An [Arcade](https://docs.arcade.dev/en/home) MCP server for **ServiceNow Security Incident Response (SIR)**. It lets an AI agent finish working a security incident: read it, record its classification and verdict, add secure notes, and move it to the next state.

It runs as a **dedicated ServiceNow service account**, not as whichever person signed in.

> This is an [Arcade Labs](https://github.com/arcadeai-labs) project: shared as-is, without support or an SLA.

> **Status: early.** Run end to end as a service account against Security Incident Response 14.4.4 on a Brazil-release instance. All three tools work. Applying security tags isn't supported; see [Known gaps](#known-gaps).

## Contents

- [Tools](#tools)
- [How authentication works](#how-authentication-works)
- [Set up ServiceNow](#set-up-servicenow)
- [Run locally](#run-locally)
- [Deploy to Arcade](#deploy-to-arcade)
- [SIR schema](#sir-schema)
- [Project layout](#project-layout)
- [Development](#development)
- [Arcade documentation](#arcade-documentation)

## Tools

| Tool | What it does |
|---|---|
| `GetSecurityIncident` | Reads a security incident by number (`SIR0010001`) or sys_id. Returns each field with both its stored value and display label, plus the incident's security tags and secure notes. |
| `ListSecurityIncidentFieldChoices` | Lists the valid values for `state`, `category`, `subcategory` (optionally filtered by category) or `business_impact`, as configured on your instance. |
| `UpdateSecurityIncident` | Sets state, category, subcategory and business impact, and optionally adds a secure note. Accepts a display label or a stored value, and checks it against the instance's choice list before writing. |

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

1. **Create the service account.** Create a ServiceNow user for the agent, marked web-service access only, with the `sn_si.analyst` role. That role was enough to read and update security incidents and to read and append secure notes in testing.
2. **Enable the client-credentials grant.** Set the system property `glide.oauth.inbound.client.credential.grant_type.enabled` to `true`.
3. **Create an OAuth client for it.** In Machine Identity Console (Zurich and later) or Application Registry (earlier releases), create an OAuth client for an integration service, with **Client Credentials** as its default grant type and the service account as its **OAuth Application User**.
4. **Copy the client ID and client secret.** You will store them in Arcade, not in this repository.

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

## SIR schema

These names are in [`constants.py`](src/servicenow_secops/constants.py). They were checked against Security Incident Response 14.4.4 with demo data on a Brazil-release instance. SIR schemas can differ between plugin versions, so re-check them (`sys_db_object` for tables, `sys_dictionary` for fields) on older releases.

| What | Where | Notes |
|---|---|---|
| Security incidents | `sn_si_incident` | Extends `sm_order`, which extends `task` |
| State, category, subcategory, business impact | Choice lists on `sn_si_incident`, read through the UI Meta API | Subcategories depend on the category's stored value. States include Analysis (16), Contain (18), Eradicate (19) and Recover (20) |
| Business impact | `business_criticality` | Integer: 1 Critical, 2 High, 3 Non-critical |
| Organization | `company` | Reference to `core_company`, inherited from `task` |
| Secure notes | `secure_notes` on `sm_order` | A single encrypted field, not a journal: writing replaces the whole value, so `UpdateSecurityIncident` reads the current notes and appends. Readable and writable with `sn_si.analyst` |
| Tags applied to an incident | `sn_sec_cmn_applied_security_tag` | Read-only here. Points at the incident with `record_table` and `record_id`, and at the tag with `security_tag` |

### Known gaps

- **Applying security tags isn't supported.** `GetSecurityIncident` reads an incident's tags, but nothing here applies them. SIR only lets server-side code create applied tags (the table's create ACL is `nobody`), the incident's `security_tags` field is filled in from those rows rather than the other way round, and ServiceNow ships no out-of-the-box API for it. This server only uses out-of-the-box APIs, so it doesn't add a custom one. To tag incidents automatically, use SIR's Security Tag Rules on the instance.
- **Choice lists come from the UI Meta API.** Tools read the instance's configured choices from `/api/now/ui/meta/sn_si_incident`, which any account that can read security incidents can call. If that's unavailable they try `sys_choice` (which needs roles such as `personalize_choices`), then fall back to the values existing incidents hold, which can miss valid ones; the tool output says when that happens.
- **Organization can't be set yet**, because it is a reference field.
- **No automated tests or [evals](https://docs.arcade.dev/en/build/create-tools/evaluate-tools) yet.**

## Project layout

```
src/servicenow_secops/
├── server.py      # MCPApp entry point; registers the tools
├── tools.py       # The three tools
├── sir.py         # Incident lookup, choice lists, and applied-tag reads
├── client.py      # ServiceNow REST calls and error mapping
├── auth.py        # Client-credentials token minting and caching
└── constants.py   # Table and field names (see "SIR schema")
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
