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
    config: { provider: { acme: { name: "Acme", models: { "acme.smart": {} } } } },
    skills: [],
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
  const noop = () => ({ editor: () => ({ set() {}, add() {} }), transform: async () => {}, reload: async () => {} })
  return {
    providers,
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
      skill: noop(),
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
  assert.deepEqual(f.providers.value[0].models.map((m) => m.id), ["acme.smart"])

  f.login(undefined)
  await settle()
  assert.deepEqual(f.providers.value, [])
})
