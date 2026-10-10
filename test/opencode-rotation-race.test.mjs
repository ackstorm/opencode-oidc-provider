// node --test test/opencode-rotation-race.test.mjs
// The cross-process race the 2026-10-10 incident lost a turn to: opencode shares
// one credential across processes and the AS invalidates a refresh token the
// moment it rotates it, so a loser's exchange gets a 4xx. Every exchange now
// journals its result; a loser adopts the winner's tokens instead of failing —
// before exchanging (the journal's `previous`), and after a 4xx (its successor).
import { test } from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs"
import { tmpdir } from "node:os"

process.env.OIDC_JOURNAL_POLL_MS = "20"
process.env.OIDC_JOURNAL_GRACE_MS = "400"
process.env.XDG_DATA_HOME = mkdtempSync(`${tmpdir()}/opencode-race-`)
const { SsoAuth, default: plugin } = await import("../index.mjs")
const HOME = `${process.env.XDG_DATA_HOME}/opencode/acme`
const JOURNAL = `${HOME}/rotation.json`
const OPTIONS = { api: "https://api.test/v1", platform: "https://api.test", provider: "acme" }

// sub() reads the JWT payload, so fake tokens name their user there.
const jwt = (sub) => `h.${Buffer.from(JSON.stringify({ sub })).toString("base64url")}.s`
const ALICE = jwt("alice")
const BOB = jwt("bob")

// What the journal would hold after another process rotated r-old away.
// `user` is the JWT sub, the way journalWrite records it.
const winnerJournal = (user = "alice") => ({ user, previous: "r-old", refresh: "r-new", access: jwt("alice"), expires: Date.now() + 3_600_000, at: Date.now() })
const journal = (entry) => {
  mkdirSync(HOME, { recursive: true })
  writeFileSync(JOURNAL, JSON.stringify(entry))
}

let tokenStatus = 200 // what the token endpoint answers; 4xx/5xx per test
let tokenCalls = 0
globalThis.fetch = async (input, init) => {
  const url = typeof input === "string" ? input : input.url
  const ok = (body) => Response.json(body)
  if (url.startsWith("https://api.test/.well-known/oauth-protected-resource")) return ok({ authorization_servers: ["https://as.test"] })
  if (url === "https://as.test/.well-known/oauth-authorization-server")
    return ok({ issuer: "https://as.test", token_endpoint: "https://as.test/token", registration_endpoint: "https://as.test/register", authorization_endpoint: "https://as.test/authorize" })
  if (url === "https://as.test/register") return ok({ client_id: "c1" })
  if (url === "https://as.test/token") {
    tokenCalls += 1
    if (tokenStatus === 200) return ok({ access_token: jwt("alice"), refresh_token: "r-new", expires_in: 3600 })
    return Response.json({ error: "invalid_grant" }, { status: tokenStatus })
  }
  if (url.startsWith("https://model.test")) return new Response(`authed:${input.headers?.get("authorization")}`)
  throw new Error(`unexpected ${url}`)
}

// The DCR identity the refresh path reads; no register call needed.
mkdirSync(HOME, { recursive: true })
writeFileSync(`${HOME}/client.json`, JSON.stringify({ issuer: "https://as.test", client_id: "c1" }))

test("v1: a 4xx lost race adopts the winner's tokens instead of failing the turn", async () => {
  tokenStatus = 400
  let auth = { type: "oauth", access: ALICE, refresh: "r-old", expires: 0 }
  const saved = []
  const client = { auth: { set: async ({ body }) => { auth = body; saved.push(body) } } }
  const provider = await SsoAuth({ client }, OPTIONS)
  const loader = await provider.auth.loader(async () => auth)
  // The other process refreshes first: its 400 lands while its journal write is
  // still in flight. The loser must poll, adopt, and keep the request alive.
  const won = winnerJournal()
  setTimeout(() => journal(won), 100)
  const r = await loader.fetch("https://model.test/x")
  assert.equal(await r.text(), `authed:Bearer ${won.access}`)
  assert.equal(tokenCalls, 1, "the stale refresh token was spent exactly once")
  assert.deepEqual(saved, [{ type: "oauth", access: won.access, refresh: "r-new", expires: won.expires }], "the store heals with the adopted token")
  tokenStatus = 200
})

test("v1: a successful refresh journals what replaced the spent token", async () => {
  tokenStatus = 200
  let auth = { type: "oauth", access: ALICE, refresh: "r-old", expires: 0 }
  const provider = await SsoAuth({ client: { auth: { set: async () => {} } } }, OPTIONS)
  const loader = await provider.auth.loader(async () => auth)
  await loader.fetch("https://model.test/x")
  const j = JSON.parse(readFileSync(JOURNAL, "utf8"))
  assert.equal(j.previous, "r-old", "the next loser can recognise its token here")
  assert.equal(j.refresh, "r-new")
  assert.equal(j.user, "alice")
})

test("v1: a 5xx is an outage, not a sign-out and not a race", async () => {
  tokenStatus = 503
  journal(winnerJournal()) // valid winner tokens, but for a token we do not hold: no adoption
  const auth = { type: "oauth", access: ALICE, refresh: "r-flaky", expires: 0 }
  const provider = await SsoAuth({ client: { auth: { set: async () => {} } } }, OPTIONS)
  const loader = await provider.auth.loader(async () => auth)
  await assert.rejects(loader.fetch("https://model.test/x"), /503/)
  tokenStatus = 200
})

// Minimal v2 ctx: setup() only needs the method registry captured and the
// config fetch to see "signed out".
function fakeCtx() {
  const methods = []
  const noop = () => ({ editor: () => ({ set() {}, add() {} }), transform: async () => {}, reload: async () => {} })
  return {
    methods,
    ctx: {
      options: OPTIONS,
      integration: {
        transform: async (fn) => fn({ update() {}, method: { update: (m) => methods.push(m) } }),
        connection: { active: async () => undefined, resolve: async () => undefined },
      },
      provider: noop(),
      mcp: noop(),
      skill: noop(),
      event: { async *subscribe() { await new Promise(() => {}) } },
    },
  }
}

const browserRefresh = async (credential) => {
  const f = fakeCtx()
  await plugin.setup(f.ctx)
  return f.methods.find((m) => m.method?.id === "sso-browser").refresh(credential)
}

test("v2: a refresh token the journal lists as `previous` is adopted, not spent", async () => {
  journal(winnerJournal())
  const before = tokenCalls
  const t = await browserRefresh({ type: "oauth", access: ALICE, refresh: "r-old", expires: 0 })
  assert.deepEqual(t, { type: "oauth", methodID: "sso-browser", refresh: "r-new", access: winnerJournal().access, expires: t.expires })
  assert.equal(tokenCalls, before, "no token call: the successor was already on disk")
})

test("v2: a 4xx lost race adopts the winner's tokens instead of failing the turn", async () => {
  tokenStatus = 400
  journal({ ...winnerJournal(), previous: null }) // a re-login, not a rotation of ours
  const before = tokenCalls
  const t = await browserRefresh({ type: "oauth", access: ALICE, refresh: "r-dead", expires: 0 })
  assert.equal(t.refresh, "r-new")
  assert.equal(tokenCalls, before + 1, "the dead token was spent exactly once")
  tokenStatus = 200
})

test("v2: a dead token nothing replaced is a sign-out, and another user's tokens are never adopted", async () => {
  tokenStatus = 400
  journal(winnerJournal(BOB)) // valid, but a different account
  await assert.rejects(browserRefresh({ type: "oauth", access: ALICE, refresh: "r-dead", expires: 0 }), /opencode auth login acme/)
  tokenStatus = 200
})
