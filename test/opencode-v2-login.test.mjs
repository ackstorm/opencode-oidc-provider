// node --test test/opencode-v2-login.test.mjs
// v2: a login in the running service (credential.switched) delivers the backend
// config without a restart; a logout takes it away.
import { test } from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"

process.env.XDG_DATA_HOME = mkdtempSync(`${tmpdir()}/opencode-v2-`)
const plugin = (await import("../index.mjs")).default

globalThis.fetch = async (input) => {
  const url = typeof input === "string" ? input : input.url
  if (url !== "https://api.test/clients/opencode/config") throw new Error(`unexpected ${url}`)
  return Response.json({
    schema: "ackstorm.opencode-config/1",
    auth: "ok",
    config: { provider: { acme: { name: "Acme", models: { "acme.smart": {}, "acme.think": { reasoning: true } } } } },
    skills: [{ name: "acme-api", version: "sha256:a", files: { "SKILL.md": "---\nname: acme-api\ndescription: Use when the user mentions Acme.\n---\nbody" } }],
  })
}

// Minimal v2 ctx: transforms are kept and re-run on reload, like core/src/state.ts.
function fakeCtx() {
  let connection
  const events = []
  let wake
  const state = (make) => {
    const fns = []
    const s = { value: make(), transform: async (fn) => fns.push(fn), reload: async () => {
      s.value = make()
      for (const fn of fns) fn(s.editor(s.value))
    } }
    return s
  }
  const providers = state(() => [])
  providers.editor = (list) => ({ add: (p) => list.push(p) })
  const skills = state(() => [])
  skills.editor = (list) => ({ add: (s) => list.push(s) })
  const noop = () => ({ editor: () => ({ set() {}, add() {} }), transform: async () => {}, reload: async () => {} })
  return {
    providers,
    skills,
    login(c) {
      connection = c
      events.push({ type: "credential.switched", data: { integrationID: "acme", credentialID: c ? "cred_1" : null } })
      wake?.()
    },
    ctx: {
      options: { api: "https://api.test/v1", platform: "https://api.test", provider: "acme" },
      integration: {
        transform: async () => {},
        connection: {
          active: async () => connection,
          resolve: async () => ({ type: "oauth", access: "a", refresh: "r", expires: Date.now() + 3_600_000 }),
        },
      },
      provider: providers,
      mcp: noop(),
      skill: skills,
      event: {
        async *subscribe() {
          for (;;) {
            while (events.length) yield events.shift()
            await new Promise((r) => (wake = r))
          }
        },
      },
    },
  }
}

const settle = () => new Promise((r) => setTimeout(r, 20))

test("v2: login and logout in the running service reload the provider", async () => {
  const f = fakeCtx()
  await plugin.setup(f.ctx)
  await f.providers.reload()
  assert.deepEqual(f.providers.value, []) // signed out at start: nothing delivered

  f.login({ type: "credential", id: "cred_1" })
  await settle()
  assert.deepEqual(f.providers.value.map((p) => p.info.id), ["acme"])
  assert.deepEqual(f.providers.value[0].models.map((m) => m.id), ["acme.smart", "acme.think"])

  // reasoning: true -> the effort variants v1 generated; anything else -> none
  const [smart, think] = f.providers.value[0].models
  assert.deepEqual(smart.variants, [])
  assert.deepEqual(think.variants, [
    { id: "low", settings: { reasoningEffort: "low" } },
    { id: "medium", settings: { reasoningEffort: "medium" } },
    { id: "high", settings: { reasoningEffort: "high" } },
  ])

  // v2 never reads the frontmatter: without the description the skill is hidden from the model
  await f.skills.reload()
  assert.deepEqual(f.skills.value.map((s) => [s.id, s.description]), [["acme-api", "Use when the user mentions Acme."]])

  f.login(undefined)
  await settle()
  assert.deepEqual(f.providers.value, [])
})

test("v2: a dead refresh token keeps the cached provider and names the re-login", async () => {
  const f = fakeCtx()
  await plugin.setup(f.ctx)
  f.login({ type: "credential", id: "cred_1" }) // fills the cache, like the test above
  await settle()

  // what core does when our refresh() throws: AuthorizationError wraps it
  f.ctx.integration.connection.resolve = async () => { throw new Error("Integration.Authorization") }
  f.login({ type: "credential", id: "cred_1" })
  await settle()
  assert.deepEqual(f.providers.value.map((p) => p.info.id), ["acme"])

  const realFetch = globalThis.fetch
  globalThis.fetch = async (input) => {
    const url = typeof input === "string" ? input : input.url
    if (url.endsWith("/.well-known/oauth-protected-resource/v1")) return Response.json({ authorization_servers: ["https://api.test"] })
    if (url.endsWith("/.well-known/oauth-authorization-server")) return Response.json({ issuer: "https://api.test", token_endpoint: "https://api.test/token" })
    if (url === "https://api.test/token") return Response.json({ error: "invalid_grant" }, { status: 400 })
    throw new Error(`unexpected ${url}`)
  }
  try {
    const { writeFile } = await import("node:fs/promises")
    await writeFile(`${process.env.XDG_DATA_HOME}/opencode/acme/client.json`, JSON.stringify({ issuer: "https://api.test", client_id: "c" }))
    let refresh
    f.ctx.integration.transform = async (fn) => fn({ update() {}, method: { update: (m) => { refresh ??= m.refresh } } })
    await plugin.setup(f.ctx)
    await assert.rejects(refresh({ refresh: "dead" }), /opencode auth login acme/)
  } finally {
    globalThis.fetch = realFetch
  }
})
