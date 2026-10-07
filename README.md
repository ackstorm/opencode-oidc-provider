# opencode-oidc-provider

OpenCode plugin for engines **v1 and v2**. Signs OpenCode in to a GenAI
platform's model gateway (OAuth: browser or device code, with automatic token
refresh) and, at every start, fills in the user's models, MCP servers and skills
from that platform's backend. The user's own config always wins.

## Install

Your platform's backend publishes this plugin, with its own options, in
`https://<origin>/.well-known/opencode`. Two commands, same on v1 and v2:

```bash
opencode auth login https://<origin>      # installs and configures the plugin
opencode auth login -p <provider>         # sign in (v2: opencode auth login <provider>)
```

Restart OpenCode to pick up backend changes. Signing in always re-discovers
the authorization server, so a moved one needs no restart (v2's background
service included).

Headless machine: pick the device-code method. On opencode v2 without a
browser, put a stub `xdg-open` on `PATH` (`printf '#!/bin/sh\necho "$1"\n'`),
or the CLI exits instead of printing the login URL.

### Manual install

```json
{
  "plugin": [
    ["git+https://github.com/ackstorm/opencode-oidc-provider.git#v0.4.0",
     {"api": "https://api.example.com/v1", "platform": "https://api.example.com", "provider": "ai-platform"}]
  ]
}
```

Install from the repo root spec: opencode v1 ignores git subdirectory
(`::path:`) specs.

## Options

| Option | Meaning |
|---|---|
| `api` | The gateway's OpenAI-compatible base URL (e.g. `https://api.example.com/v1`). OAuth discovery starts here (RFC 9728 → RFC 8414). |
| `platform` | The origin serving `/clients/*`. Config comes from `<platform>/clients/opencode/config` (schema `ackstorm.opencode-config/1`). |
| `provider` | The OpenCode provider id: the name in the login picker, the model prefix (`<provider>/<model>`), and the plugin's data folder. |

A `platform.json` with the same fields next to `index.mjs` is read as defaults
(tarball installs); plugin options override it.

## Backend manifest

What the backend serves at `/.well-known/opencode` (unauthenticated; public data only):

```json
{
  "auth": {"command": ["echo", "Sign in with: opencode auth login -p <provider>"], "env": ""},
  "config": {
    "plugin": [["git+https://github.com/ackstorm/opencode-oidc-provider.git#v0.4.0",
                {"api": "https://<origin>/v1", "platform": "https://<origin>", "provider": "<provider>"}]]
  }
}
```

OpenCode requires `auth`; this plugin does not use the credential it creates.
Pin a tag; bump it in the manifest to roll out a new plugin version.

## Engines

One file serves both: v1 loads `default.server` (`SsoAuth`, the `auth` +
`config` hooks), v2 loads `default.setup` (integration OAuth methods with
`refresh`, plus provider/MCP/skill transforms). v2 injects the credential by
`integrationID` and refreshes it 5 minutes before expiry.

The server's `model` / `small_model` (`<provider>/<name>`) are applied as defaults
on **v1 only**; the user's own `model` / `small_model` win. v2 ignores them for now
(its core has `model.transform` → `default.set`, but plugin access is unverified).

## Files it writes (`$XDG_DATA_HOME/opencode`, default `~/.local/share/opencode`)

| File | Content |
|---|---|
| `<provider>/client.json` | The dynamic client registration (client id). |
| `<provider>/config.json` | Last good backend config (0600), used for 30 days when the backend is down. |
| `<provider>/skills/<name>/SKILL.md` | Skills delivered by the backend. |

Tokens live in OpenCode's own credential store; the plugin never writes it.
