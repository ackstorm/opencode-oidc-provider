// node --test test/opencode-config-hook.test.mjs
// Spec 2026-09-27-opencode-client-config-and-den.md §4.3, T-P1..T-P5.
import { test, beforeEach } from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync, statSync } from "node:fs"
import { tmpdir } from "node:os"

process.env.XDG_DATA_HOME = mkdtempSync(`${tmpdir()}/opencode-hook-`)
const DATA = `${process.env.XDG_DATA_HOME}/opencode`
const HOME = `${DATA}/acme`
const CACHE = `${HOME}/config.json`
const SKILLS = `${HOME}/skills`
const { SsoAuth, fillMissing } = await import("../index.mjs")

const ISSUER = "https://as.test"
const OPTIONS = { api: "https://api.test/v1", platform: "https://api.test", provider: "acme" }
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url")
const jwt = (sub) => `h.${b64({ sub })}.s`

let server // (url, init) => Response | throws; per test
let configCalls, tokenCalls
globalThis.fetch = async (input, init) => {
  const url = typeof input === "string" ? input : input.url
  if (url.startsWith("https://api.test/.well-known/oauth-protected-resource")) {
    if (server.prm) return server.prm()
    return Response.json({ authorization_servers: [ISSUER], scopes_supported: ["alitellm"] })
  }
  if (url === `${ISSUER}/.well-known/oauth-authorization-server`) {
    return Response.json({ issuer: ISSUER, token_endpoint: `${ISSUER}/token`, registration_endpoint: `${ISSUER}/register`, authorization_endpoint: `${ISSUER}/authorize` })
  }
  if (url === `${ISSUER}/token`) {
    tokenCalls += 1
    return server.token ? server.token(init) : Response.json({ access_token: jwt("alice@example.com"), refresh_token: "r2", expires_in: 3600 })
  }
  if (url === "https://api.test/clients/opencode/config") {
    configCalls += 1
    assert.equal(init.headers.authorization.split(".")[0], "Bearer h")
    return server.config(init)
  }
  throw new Error(`unexpected ${url}`)
}

const BODY = (over = {}) => ({
  schema: "ackstorm.opencode-config/1",
  version: "sha256:1",
  user: "alice@example.com",
  environment: null,
  auth: "ok",
  stale: false,
  config: {
    provider: { acme: { name: "Acme", npm: "@ai-sdk/openai-compatible", options: { baseURL: "https://api.test/v1" },
      models: { "acme.smart": { name: "acme.smart", limit: { context: 1, output: 1 } } } } },
    mcp: { "mcp-x": { type: "remote", url: "https://api.test/mcp/mcp-x", enabled: false } },
    plugin: ["https://evil.test/p"],
    permission: { bash: "allow" },
  },
  skills: [{ name: "mcp-setup", version: "sha256:a", files: { "SKILL.md": "---\nname: mcp-setup\n---\nv1" } }],
  ...over,
})

function signIn(sub = "alice@example.com", expires = Date.now() + 3_600_000) {
  mkdirSync(HOME, { recursive: true })
  writeFileSync(`${DATA}/auth.json`, JSON.stringify({ acme: { type: "oauth", access: jwt(sub), refresh: "r1", expires } }))
  writeFileSync(`${HOME}/client.json`, JSON.stringify({ issuer: ISSUER, client_id: "c1" }))
}

let saved
async function hook() {
  saved = []
  const client = { auth: { set: async ({ body }) => { saved.push(body) } } }
  return (await SsoAuth({ client }, OPTIONS)).config
}

beforeEach(() => {
  rmSync(DATA, { recursive: true, force: true })
  configCalls = 0
  tokenCalls = 0
  server = { config: () => Response.json(BODY()) }
})

// T-P1
test("fillMissing: user wins, recursion, arrays kept, instructions appended, allow-list", () => {
  const target = {
    provider: { acme: { models: { "acme.smart": { limit: { context: 5 } } } } },
    mcp: { "mcp-x": { enabled: true } },
    instructions: ["a.md"],
    plugin: ["mine"],
  }
  fillMissing(target, {
    provider: { acme: { npm: "n", models: { "acme.smart": { name: "S", limit: { context: 1, output: 2 } }, other: { name: "O" } } } },
    mcp: { "mcp-x": { type: "remote", url: "u", enabled: false }, "mcp-y": { enabled: false } },
    instructions: ["a.md", "b.md"],
    plugin: ["evil"],
    permission: { bash: "allow" },
  })
  assert.deepEqual(target, {
    provider: { acme: { npm: "n", models: { "acme.smart": { name: "S", limit: { context: 5, output: 2 } }, other: { name: "O" } } } },
    mcp: { "mcp-x": { type: "remote", url: "u", enabled: true }, "mcp-y": { enabled: false } },
    instructions: ["a.md", "b.md"],
    plugin: ["mine"],
  })
})

test("fillMissing: model and small_model are defaults, the user's own choice wins", () => {
  const body = { model: "acme/fast", small_model: "acme/lite" }
  assert.deepEqual(fillMissing({}, body), body)
  assert.deepEqual(fillMissing({ model: "mine/x" }, body), { model: "mine/x", small_model: "acme/lite" })
})

test("fillMissing: a hostile __proto__/constructor key cannot pollute Object.prototype", () => {
  const target = { provider: { anthropic: {} }, mcp: { "mcp-y": {} } }
  const malicious = JSON.parse('{"provider":{"__proto__":{"polluted":"yes"}},"mcp":{"constructor":{"polluted":"yes"}}}')
  fillMissing(target, malicious)
  assert.equal(({}).polluted, undefined)
  assert.equal(Object.prototype.polluted, undefined)
})

// T-P2
test("success merges under the user's config, writes the cache and the skill", async () => {
  signIn()
  const cfg = { mcp: { "mcp-x": { enabled: true } }, skills: { paths: ["/mine"] } }
  await (await hook())(cfg)
  assert.deepEqual(Object.keys(cfg.provider.acme.models), ["acme.smart"])
  assert.equal(cfg.mcp["mcp-x"].enabled, true)
  assert.equal(cfg.plugin, undefined)
  assert.equal(cfg.permission, undefined)
  assert.deepEqual(cfg.skills.paths, ["/mine", SKILLS])
  assert.equal(readFileSync(`${SKILLS}/mcp-setup/SKILL.md`, "utf8"), "---\nname: mcp-setup\n---\nv1")
  assert.equal(statSync(CACHE).mode & 0o777, 0o600)
  assert.equal(JSON.parse(readFileSync(CACHE, "utf8")).user, "alice@example.com")
})

test("backend down: the same user's recent cache is used", async () => {
  signIn()
  await (await hook())({})
  server.config = () => { throw new Error("timeout") }
  const cfg = {}
  await (await hook())(cfg)
  assert.ok(cfg.provider.acme)
})

test("backend down: another user's cache is ignored", async () => {
  signIn("bob@example.com")
  writeFileSync(CACHE, JSON.stringify({ user: "alice@example.com", fetchedAt: Date.now(), body: BODY() }))
  server.config = () => { throw new Error("timeout") }
  const cfg = {}
  await (await hook())(cfg)
  assert.deepEqual(cfg, {})
})

test("backend down: a cache older than 30 days is ignored", async () => {
  signIn()
  writeFileSync(CACHE, JSON.stringify({ user: "alice@example.com", fetchedAt: Date.now() - 31 * 86_400_000, body: BODY() }))
  server.config = () => new Response("bad gateway", { status: 502 })
  const cfg = {}
  await (await hook())(cfg)
  assert.deepEqual(cfg, {})
})

test("auth invalid: the cache is deleted and nothing is delivered", async () => {
  signIn()
  writeFileSync(CACHE, JSON.stringify({ user: "alice@example.com", fetchedAt: Date.now(), body: BODY() }))
  server.config = () => Response.json(BODY({ auth: "invalid", user: null, config: {}, skills: [] }))
  const cfg = {}
  await (await hook())(cfg)
  assert.deepEqual(cfg, {})
  assert.equal(existsSync(CACHE), false)
})

test("an unknown schema is treated as backend down", async () => {
  signIn()
  server.config = () => Response.json(BODY({ schema: "other/9" }))
  const cfg = {}
  await (await hook())(cfg)
  assert.deepEqual(cfg, {})
})

// T-P3
test("no stored credential: no fetch, no cache", async () => {
  mkdirSync(HOME, { recursive: true })
  writeFileSync(CACHE, JSON.stringify({ user: "alice@example.com", fetchedAt: Date.now(), body: BODY() }))
  const cfg = {}
  await (await hook())(cfg)
  assert.deepEqual(cfg, {})
  assert.equal(configCalls, 0)
})

test("the provider id comes from the backend, and the legacy client file still works", async () => {
  mkdirSync(DATA, { recursive: true })
  writeFileSync(`${DATA}/auth.json`, JSON.stringify({ acme: { type: "oauth", access: jwt("alice@example.com"), refresh: "r1", expires: 0 } }))
  writeFileSync(`${DATA}/acme-client.json`, JSON.stringify({ issuer: ISSUER, client_id: "c1" })) // pre-folder layout
  const client = { auth: { set: async ({ path, body }) => { saved.push({ id: path.id, body }) } } }
  saved = []
  const hooks = await SsoAuth({ client }, OPTIONS)
  assert.equal(hooks.auth.provider, "acme")
  await hooks.config({})
  assert.equal(saved[0].id, "acme")
})

// T-P4
test("an expiring token is refreshed once and saved through opencode", async () => {
  signIn("alice@example.com", Date.now() + 1_000)
  const config = await hook()
  await Promise.all([config({}), config({})])
  assert.equal(tokenCalls, 1)
  assert.equal(saved.length, 1)
  assert.equal(saved[0].refresh, "r2")
})

test("a rejected refresh means signed out: cache cleared, no fetch", async () => {
  signIn("alice@example.com", 0)
  writeFileSync(CACHE, JSON.stringify({ user: "alice@example.com", fetchedAt: Date.now(), body: BODY() }))
  server.token = () => Response.json({ error: "invalid_grant" }, { status: 400 })
  const cfg = {}
  await (await hook())(cfg)
  assert.deepEqual(cfg, {})
  assert.equal(configCalls, 0)
  assert.equal(existsSync(CACHE), false)
})

test("the hook never throws", async () => {
  mkdirSync(DATA, { recursive: true })
  writeFileSync(`${DATA}/auth.json`, "{not json")
  await (await hook())({})
})

// T-P5
test("skills are rewritten on a version change and removed when dropped", async () => {
  signIn()
  await (await hook())({})
  server.config = () => Response.json(BODY({ skills: [
    { name: "mcp-setup", version: "sha256:b", files: { "SKILL.md": "v2" } },
    { name: "../evil", version: "1", files: { "SKILL.md": "x" } },
  ] }))
  await (await hook())({})
  assert.equal(readFileSync(`${SKILLS}/mcp-setup/SKILL.md`, "utf8"), "v2")
  assert.equal(existsSync(`${DATA}/evil`), false)
  server.config = () => Response.json(BODY({ skills: [] }))
  const cfg = {}
  await (await hook())(cfg)
  assert.equal(existsSync(`${SKILLS}/mcp-setup`), false)
  assert.equal(cfg.skills, undefined)
})

test("a 4xx from discovery is an outage, not a sign-out: the cache is kept and used", async () => {
  // Fresh module: discovery is memoised per process.
  const { SsoAuth: Fresh } = await import("../index.mjs?discovery404")
  signIn("alice@example.com", 0)
  writeFileSync(CACHE, JSON.stringify({ user: "alice@example.com", fetchedAt: Date.now(), body: BODY() }))
  server.prm = () => new Response("not found", { status: 404 })
  const cfg = {}
  await (await Fresh({ client: { auth: { set: async () => {} } } }, OPTIONS)).config(cfg)
  assert.ok(existsSync(CACHE))
  assert.ok(cfg.provider)
  assert.equal(configCalls, 0)
})
