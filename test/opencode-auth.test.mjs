// node --test test/opencode-auth.test.mjs
// The three behaviours the 2026-09 audit reproduced, pinned against a fake AS:
// a refresh race must not spend a rotated token, a failed discovery must not
// poison the process, and a stray loopback hit must not consume the listener.
import { test } from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"

process.env.XDG_DATA_HOME = mkdtempSync(`${tmpdir()}/opencode-auth-`)
const { SsoAuth } = await import("../index.mjs")

const ISSUER = "https://as.test"
const calls = []
let discoveryFails = false
let tokenCalls = 0
let devicePolls = 0
globalThis.fetch = async (input, init) => {
  const url = typeof input === "string" ? input : input.url
  calls.push(url)
  const ok = (body) => new Response(JSON.stringify(body), { status: 200 })
  if (url.startsWith("https://api.test/.well-known/oauth-protected-resource")) {
    if (discoveryFails) throw new Error("network down")
    return ok({ authorization_servers: [ISSUER], scopes_supported: ["alitellm"] })
  }
  if (url === `${ISSUER}/.well-known/oauth-authorization-server`) {
    return ok({ issuer: ISSUER, token_endpoint: `${ISSUER}/token`, registration_endpoint: `${ISSUER}/register`, authorization_endpoint: `${ISSUER}/authorize`, device_authorization_endpoint: `${ISSUER}/device_authorization` })
  }
  if (url === `${ISSUER}/device_authorization`) {
    return ok({ device_code: "dc-1", user_code: "BCDF-GHJK", verification_uri: `${ISSUER}/device`, verification_uri_complete: `${ISSUER}/device?user_code=BCDF-GHJK`, expires_in: 600, interval: 0.01 })
  }
  if (url === `${ISSUER}/register`) return ok({ client_id: "c1" })
  if (url === `${ISSUER}/token`) {
    const form = new URLSearchParams(init.body)
    if (form.get("grant_type") === "urn:ietf:params:oauth:grant-type:device_code") {
      devicePolls += 1
      if (devicePolls < 2) return new Response(JSON.stringify({ error: "authorization_pending" }), { status: 400 })
      return ok({ access_token: "a-device", refresh_token: "r-current", expires_in: 3600 })
    }
    if (form.get("refresh_token") !== "r-current") return new Response("{}", { status: 400 })
    tokenCalls += 1
    return ok({ access_token: `a${tokenCalls}`, refresh_token: "r-current", expires_in: 3600 })
  }
  if (url.startsWith("https://model.test")) return new Response(`authed:${(input.headers?.get?.("authorization") ?? init?.headers?.authorization)}`)
  throw new Error(`unexpected ${url}`)
}

const OPTIONS = { api: "https://api.test/v1", platform: "https://api.test", provider: "acme" }

function fakeClient() {
  let auth = { type: "oauth", access: "stale", refresh: "r-current", expires: 0 }
  return {
    client: {
      auth: { set: async ({ body }) => { auth = body } },
    },
    getAuth: async () => auth,
    setAuth: (a) => { auth = a },
  }
}

test("a login registers once and a refresh reuses that identity", async () => {
  const f = fakeClient()
  const plugin = await SsoAuth({ client: f.client }, OPTIONS)
  assert.equal(plugin.auth.provider, "acme")
  const { url, callback } = await plugin.auth.methods[0].authorize()
  assert.match(url, /client_id=c1/)
  // Deliver the callback ourselves on the listener the plugin opened.
  const u = new URL(url)
  const redirect = new URL(u.searchParams.get("redirect_uri"))
  const stray = await fetchRaw(redirect, "state=wrong&code=x")
  assert.equal(stray.status, 400, "a stray hit is rejected without closing the listener")
  const good = await fetchRaw(redirect, `state=${u.searchParams.get("state")}&code=code-1`)
  assert.equal(good.status, 200)
  // The AS here only knows refresh tokens, so the code exchange fails; what
  // matters is that the listener survived the stray hit and delivered the code.
  assert.equal((await callback()).type, "failed")
  assert.equal(calls.filter((c) => c.endsWith("/register")).length, 1)

  // Refresh path: two overlapping requests, one token call.
  const loader = await plugin.auth.loader(f.getAuth)
  const [r1, r2] = await Promise.all([loader.fetch("https://model.test/x"), loader.fetch("https://model.test/x")])
  assert.equal(await r1.text(), "authed:Bearer a1")
  assert.equal(await r2.text(), "authed:Bearer a1")
  assert.equal(tokenCalls, 1)

  // The race the audit found: a caller that read the pre-refresh auth arrives
  // after `refreshing` cleared. It must re-read and NOT spend the old token.
  const before = tokenCalls
  // First read returns the pre-refresh auth; every later read sees the refreshed one.
  const reads = [{ type: "oauth", access: "stale", refresh: "r-old", expires: 0 }]
  const fresh = { type: "oauth", access: "a-fresh", refresh: "r-current", expires: Date.now() + 3600_000 }
  const racyLoader = await plugin.auth.loader(async () => reads.shift() ?? fresh)
  assert.equal(await (await racyLoader.fetch("https://model.test/x")).text(), "authed:Bearer a-fresh")
  assert.equal(tokenCalls, before, "no token call was made with the rotated refresh token")
})

test("a failed discovery is retried on the next call", async () => {
  // Discovery is cached per module instance; take a fresh one.
  const { SsoAuth: Fresh } = await import("../index.mjs?fresh")
  const f = fakeClient()
  const plugin = await Fresh({ client: f.client }, OPTIONS)
  const loader = await plugin.auth.loader(f.getAuth)
  discoveryFails = true
  await assert.rejects(loader.fetch("https://model.test/x"), /network down/)
  discoveryFails = false
  assert.equal(await (await loader.fetch("https://model.test/x")).text(), "authed:Bearer a2")
})

async function fetchRaw(redirect, query) {
  const { request } = await import("node:http")
  return new Promise((resolve, reject) => {
    request({ host: redirect.hostname, port: redirect.port, path: `/callback?${query}` }, (res) => {
      res.resume()
      res.on("end", () => resolve({ status: res.statusCode }))
    }).on("error", reject).end()
  })
}

test("the device method opens the verification URL and polls until the user has signed in", async () => {
  const f = fakeClient()
  const plugin = await SsoAuth({ client: f.client })
  const method = plugin.auth.methods[1]
  assert.match(method.label, /device code/)
  const { url, instructions, callback } = await method.authorize()
  assert.equal(url, `${ISSUER}/device?user_code=BCDF-GHJK`)
  assert.match(instructions, /BCDF-GHJK/)
  const result = await callback()
  assert.equal(result.type, "success")
  assert.equal(result.access, "a-device")
  assert.equal(devicePolls, 2, "one authorization_pending, then the token")
  // Loopback stays the default method (OpenWork and the CLI take methods[0]).
  assert.equal(plugin.auth.methods[0].label, "SSO (browser)")
})

test("the legacy install (no platform.json, no options) still discovers from the configured provider", async () => {
  const { SsoAuth: Legacy } = await import("../index.mjs?legacy")
  const { client } = fakeClient()
  client.config = { providers: async () => ({ data: { providers: [{ id: "ai-platform", options: { baseURL: "https://api.test/v1" } }] } }) }
  const hooks = await Legacy({ client })
  assert.equal(hooks.auth.provider, "ai-platform")
  const { url } = await hooks.auth.methods[1].authorize()
  assert.match(url, /^https:\/\/as\.test\/device/)
})
