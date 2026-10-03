// opencode plugin (engines v1 and v2): SSO (OAuth) sign-in to a GenAI platform
// backend's model gateway, and that backend's per-user OpenCode config at every start.
//
//   opencode auth login https://<origin>     # installs this plugin via <origin>/.well-known/opencode
//   opencode auth login -p <provider>        # v2: opencode auth login <provider>
//
// Product-neutral: the backend supplies {"api": "<gateway>/v1", "platform": "<origin
// serving /clients/*>", "provider": "<id>"} as plugin options (from its .well-known
// manifest), or in a platform.json next to this file (tarball installs). See README.md.
//
// Sign-in: `api` -> RFC 9728 protected-resource document -> RFC 8414 AS metadata;
// browser (loopback + PKCE) or RFC 8628 device grant. opencode stores the tokens
// (auth.json) but never refreshes them: `fresh()` does, for every model request
// and for the config fetch.
//
// Config: the `config` hook fetches <platform>/clients/opencode/config
// (ackstorm.opencode-config/1) and fills in what the user's own config lacks.
// The user's config always wins. The provider id comes from platform.json
// (`provider`).
import { createServer } from "node:http"
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises"
import { randomBytes, createHash } from "node:crypto"

// The provider id and data folder come from the backend (platform.json
// `provider`, or plugin options). ponytail: one backend per opencode process, so
// module-level; set once in SsoAuth before anything reads it.
let PROVIDER = "ai-platform"
const PROVIDER_ID = /^[a-z0-9][a-z0-9-]{0,63}$/
const DATA = `${process.env.XDG_DATA_HOME ?? `${process.env.HOME}/.local/share`}/opencode`
const AUTH_FILE = `${DATA}/auth.json` // opencode's own credential store: read only, never written here
const paths = () => ({
  client: `${DATA}/${PROVIDER}/client.json`, // DCR result; opencode has no plugin KV
  legacyClient: `${DATA}/${PROVIDER}-client.json`, // layout before the per-provider folder
  cache: `${DATA}/${PROVIDER}/config.json`,
  skills: `${DATA}/${PROVIDER}/skills`,
})
const CONFIG_SCHEMA = "ackstorm.opencode-config/1"
const CONFIG_KEYS = ["provider", "mcp", "instructions", "model", "small_model"] // anything else the server sends is ignored
const CACHE_MAX_AGE = 30 * 86_400_000
const SKILL_NAME = /^[a-z0-9]+(?:-[a-z0-9]+)*$/
const b64 = (b) => Buffer.from(b).toString("base64url")

async function json(url, init) {
  const r = await fetch(url, { signal: AbortSignal.timeout(15_000), ...init })
  if (!r.ok) throw Object.assign(new Error(`${r.status} ${url}`), { status: r.status })
  return r.json()
}

// Where this plugin's backend is. platform.json is written into the tarball by
// the backend that served it; options come from ["<url>", {...}] in opencode.json.
let platformFile
async function backend(options) {
  platformFile ??= readFile(new URL("./platform.json", import.meta.url), "utf8")
    .then(JSON.parse)
    .catch(() => ({}))
  return { ...(await platformFile), ...options }
}

async function apiUrl(client, options) {
  const { api } = await backend(options)
  if (api) return api
  // ponytail: installs from before platform.json read the provider from config
  // (the served api.json). Drop once every user has reinstalled.
  const { data } = await client.config.providers()
  const provider = data?.providers?.find((p) => p.id === PROVIDER)
  return Object.values(provider?.models ?? {})[0]?.api?.url ?? provider?.options?.baseURL
}

// API URL -> protected-resource document (RFC 9728) -> authorization-server
// metadata (RFC 8414). Once per process.
let discovered
function discover(client, options) {
  return (discovered ??= (async () => {
    const api = await apiUrl(client, options)
    if (!api) throw new Error(`no backend for ${PROVIDER}: run \`opencode auth login https://<origin>\` to install it with its options`)
    const u = new URL(api)
    const prm = await json(`${u.origin}/.well-known/oauth-protected-resource${u.pathname.replace(/\/$/, "")}`)
    const issuer = prm.authorization_servers[0]
    const as = await json(`${issuer}/.well-known/oauth-authorization-server`)
    if (as.issuer !== issuer) throw new Error(`issuer mismatch: ${as.issuer} != ${issuer}`) // RFC 8414 §3.3
    return { issuer, as, scope: (prm.scopes_supported ?? []).join(" ") }
  })().catch((e) => { discovered = undefined; throw e })) // a blip must not poison the process
}

// The saved DCR identity, or null. A refresh token belongs to the client that
// obtained it, so a refresh must never register a new one (login does).
async function savedClientId(issuer) {
  for (const file of [paths().client, paths().legacyClient]) {
    try {
      const saved = JSON.parse(await readFile(file, "utf8"))
      if (saved.issuer === issuer) return saved.client_id
    } catch {}
  }
  return null
}

async function clientId({ issuer, as }) {
  const saved = await savedClientId(issuer)
  if (saved) return saved
  const { client_id } = await json(as.registration_endpoint, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      client_name: "opencode",
      // Loopback: the AS ignores the port (RFC 8252 §7.3), so one registration
      // serves whichever port the listener gets.
      redirect_uris: ["http://127.0.0.1/callback"],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    }),
  })
  await mkdir(`${DATA}/${PROVIDER}`, { recursive: true, mode: 0o700 })
  await writeFile(paths().client, JSON.stringify({ issuer, client_id }), { mode: 0o600 })
  return client_id
}

async function token({ as }, form) {
  const j = await json(as.token_endpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(form),
  })
  return { access: j.access_token, refresh: j.refresh_token, expires: Date.now() + j.expires_in * 1000 }
}

// One in-flight refresh per process, shared by loader.fetch and the config hook.
// ponytail: a lost race across processes spends a rotated refresh token.
let refreshing
// Tokens from a refresh whose client.auth.set failed; preferred until saved.
let unsaved
async function fresh(cur, { client, options, getAuth }) {
  if (unsaved && unsaved.expires > (cur?.expires ?? 0)) cur = unsaved
  if (cur.expires >= Date.now() + 60_000) return cur
  refreshing ??= (async () => {
    // Re-read: a caller that read stale auth just after the previous refresh
    // cleared would otherwise spend an already-rotated token.
    const again = (await getAuth()) ?? cur
    if (again?.type === "oauth" && again.expires >= Date.now() + 60_000) return again
    const d = await discover(client, options)
    const client_id = await savedClientId(d.issuer)
    if (!client_id) throw new Error(`SSO client identity lost, run \`opencode auth login -p ${PROVIDER}\``)
    const t = {
      type: "oauth",
      // Only the token endpoint's 4xx means "signed out"; a 4xx from discovery
      // (a misrouted .well-known) is an outage, not a revoked session.
      ...(await token(d, { grant_type: "refresh_token", refresh_token: again.refresh, client_id }).catch((e) => {
        throw Object.assign(e, { signedOut: e.status >= 400 && e.status < 500 })
      })),
    }
    t.refresh ||= again.refresh
    try {
      await client.auth.set({ path: { id: PROVIDER }, body: t })
      unsaved = undefined
    } catch {
      unsaved = t // opencode's store unreachable: never lose a rotated refresh token
    }
    return t
  })().finally(() => { refreshing = undefined })
  return refreshing
}

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v)

function fill(target, source) {
  if (target === undefined) return structuredClone(source)
  if (!isObject(target) || !isObject(source)) return target // the user's value wins
  for (const [k, v] of Object.entries(source)) {
    // __proto__/constructor/prototype from a hostile backend must never reach
    // Object.prototype via bracket assignment on an already-existing target.
    if (k === "__proto__" || k === "constructor" || k === "prototype") continue
    target[k] = fill(target[k], v)
  }
  return target
}

// Backend config UNDER the user's: only allow-listed keys, a key the user set
// always wins, `instructions` gains the entries it lacks.
export function fillMissing(target, source) {
  for (const key of CONFIG_KEYS) {
    const value = source?.[key]
    if (value === undefined) continue
    if (key === "instructions") {
      if (!Array.isArray(value) || (target.instructions !== undefined && !Array.isArray(target.instructions))) continue
      target.instructions = [...(target.instructions ?? [])]
      for (const x of value) if (!target.instructions.includes(x)) target.instructions.push(x)
    } else target[key] = fill(target[key], value)
  }
  return target
}

const readJson = (path) => readFile(path, "utf8").then(JSON.parse).catch(() => null)
const sub = (access) => { try { return JSON.parse(Buffer.from(access.split(".")[1], "base64url")).sub } catch { return null } }

async function writePrivate(path, text) {
  await mkdir(`${DATA}/${PROVIDER}`, { recursive: true, mode: 0o700 })
  await writeFile(path, text, { mode: 0o600 })
}

// Skills as native opencode skills: one dir per skill, rewritten only when its
// version changes, removed when the backend stops listing it. Names are
// kebab-case, so a name can never leave the skills dir.
async function writeSkills(skills) {
  const dir = paths().skills
  const keep = new Set()
  await mkdir(dir, { recursive: true, mode: 0o700 })
  for (const s of (Array.isArray(skills) ? skills : []).slice(0, 50)) {
    const md = s?.files?.["SKILL.md"]
    if (typeof s?.name !== "string" || s.name.length > 64 || !SKILL_NAME.test(s.name)) continue
    if (typeof md !== "string" || md.length > 256 * 1024) continue
    keep.add(s.name)
    const skillDir = `${dir}/${s.name}`
    if ((await readFile(`${skillDir}/.version`, "utf8").catch(() => null)) === String(s.version)) continue
    await mkdir(skillDir, { recursive: true, mode: 0o700 })
    await writeFile(`${skillDir}/SKILL.md`, md, { mode: 0o600 })
    await writeFile(`${skillDir}/.version`, String(s.version), { mode: 0o600 })
  }
  for (const name of await readdir(dir)) {
    if (!keep.has(name)) await rm(`${dir}/${name}`, { recursive: true, force: true })
  }
  return keep.size > 0
}

async function fetchConfig(platform, access) {
  if (!platform) return null
  try {
    const r = await fetch(`${platform.replace(/\/$/, "")}/clients/opencode/config`, {
      headers: { authorization: `Bearer ${access}` },
      signal: AbortSignal.timeout(2_000),
    })
    if (!r.ok) return null
    const body = await r.json()
    return body?.schema === CONFIG_SCHEMA ? body : null
  } catch {
    return null
  }
}

// The config hook. Signed out → nothing (not even the cache). Backend down →
// the same user's cache if < 30 d. Never throws; errors mean "no backend config".
async function applyConfig(cfg, { client, options }) {
  const getAuth = async () => (await readJson(AUTH_FILE))?.[PROVIDER]
  const stored = await getAuth()
  if (stored?.type !== "oauth") return
  const forget = () => rm(paths().cache, { force: true })
  let auth = null
  try {
    auth = await fresh(stored, { client, options, getAuth })
  } catch (e) {
    if (e.signedOut) return forget() // refresh token rejected
    // AS unreachable: an expired access token would read as "invalid", so use the cache.
  }
  let body = auth ? await fetchConfig((await backend(options)).platform, auth.access) : null
  if (body?.auth === "invalid") return forget()
  if (body) {
    await writePrivate(paths().cache, JSON.stringify({ user: body.user, fetchedAt: Date.now(), body }))
  } else {
    const cache = await readJson(paths().cache)
    if (!cache || cache.user !== sub(stored.access) || Date.now() - cache.fetchedAt > CACHE_MAX_AGE) return
    body = cache.body
  }
  fillMissing(cfg, body.config ?? {})
  if (await writeSkills(body.skills)) {
    cfg.skills = isObject(cfg.skills) ? cfg.skills : {}
    cfg.skills.paths = Array.isArray(cfg.skills.paths) ? cfg.skills.paths : []
    if (!cfg.skills.paths.includes(paths().skills)) cfg.skills.paths.push(paths().skills)
  }
}

// RFC 8628 §3.4–3.5: poll /token every `interval` until the user has signed
// in on the other browser; authorization_pending keeps going, slow_down adds
// 5 s, anything else (expired_token, access_denied) ends it.
async function pollDevice(d, form, interval, expiresIn) {
  const deadline = Date.now() + expiresIn * 1000
  let wait = (interval || 5) * 1000
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
  for (;;) {
    await sleep(wait)
    const r = await fetch(d.as.token_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(form),
      signal: AbortSignal.timeout(15_000),
    })
    const j = await r.json()
    if (r.ok) return { access: j.access_token, refresh: j.refresh_token, expires: Date.now() + j.expires_in * 1000 }
    if (j.error === "slow_down") wait += 5000
    else if (j.error !== "authorization_pending") throw new Error(j.error ?? `${r.status}`)
    if (Date.now() > deadline) throw new Error("the code expired before you signed in")
  }
}

// Loopback listener on a random port; resolves the code once, then closes.
function listen(state) {
  let done
  const code = new Promise((res, rej) => (done = { res, rej }))
  const server = createServer((req, res) => {
    const u = new URL(req.url, "http://127.0.0.1")
    if (u.pathname !== "/callback") return res.writeHead(404).end()
    // A stray hit must not consume the listener: the real callback is still coming.
    if (u.searchParams.get("state") !== state) return res.writeHead(400).end("state mismatch")
    res.end("Authorisation received. You can close this tab.")
    server.close()
    const c = u.searchParams.get("code")
    c ? done.res(c) : done.rej(new Error(u.searchParams.get("error") ?? "no code"))
  })
  setTimeout(() => { server.close(); done.rej(new Error("login timed out")) }, 5 * 60_000).unref()
  code.catch(() => {}) // marks the rejection handled if the user abandons the login
  const port = new Promise((res, rej) => {
    server.once("error", rej)
    server.listen(0, "127.0.0.1", () => res(server.address().port))
  })
  return { port, code }
}

export async function SsoAuth({ client }, options = {}) {
  const { provider } = await backend(options)
  if (PROVIDER_ID.test(provider ?? "")) PROVIDER = provider
  return {
    auth: {
      provider: PROVIDER,
      async loader(getAuth) {
        return {
          apiKey: "", // falsy: openai-compatible adds no Authorization; fetch sets it per request
          async fetch(input, init) {
            let auth = await getAuth()
            if (auth?.type !== "oauth") return fetch(input, init)
            auth = await fresh(auth, { client, options, getAuth })
            const req = new Request(input, init) // normalises url/Request + any headers shape
            req.headers.set("authorization", `Bearer ${auth.access}`)
            return fetch(req)
          },
        }
      },
      methods: [
        {
          type: "oauth",
          label: "SSO (browser)",
          async authorize() {
            const d = await discover(client, options)
            const verifier = b64(randomBytes(32))
            const state = b64(randomBytes(16))
            const client_id = await clientId(d) // before the listener: a failure here must not leave a port waiting
            const { port, code } = listen(state)
            const redirect_uri = `http://127.0.0.1:${await port}/callback`
            const url = new URL(d.as.authorization_endpoint)
            url.search = new URLSearchParams({
              response_type: "code",
              client_id,
              redirect_uri,
              scope: d.scope,
              state,
              code_challenge: b64(createHash("sha256").update(verifier).digest()),
              code_challenge_method: "S256",
            })
            return {
              url: url.toString(),
              method: "auto",
              instructions: "Open the URL in your browser and sign in with your organization account.",
              async callback() {
                try {
                  const t = await token(d, { grant_type: "authorization_code", code: await code, redirect_uri, client_id, code_verifier: verifier })
                  return { type: "success", ...t }
                } catch {
                  return { type: "failed" }
                }
              },
            }
          },
        },
        {
          type: "oauth",
          label: "SSO (device code — sign in from another browser)",
          async authorize() {
            const d = await discover(client, options)
            if (!d.as.device_authorization_endpoint) throw new Error("the authorization server does not offer the device grant")
            const client_id = await clientId(d)
            const da = await json(d.as.device_authorization_endpoint, {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({ client_id }),
            })
            return {
              url: da.verification_uri_complete ?? da.verification_uri,
              method: "auto",
              instructions: `Open the URL in any browser (this or another machine), confirm the code ${da.user_code} and sign in. This session completes on its own.`,
              async callback() {
                try {
                  const t = await pollDevice(d, { grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: da.device_code, client_id }, da.interval, da.expires_in)
                  return { type: "success", ...t }
                } catch {
                  return { type: "failed" }
                }
              },
            }
          },
        },
      ],
    },
    // Runs at every opencode start, before providers/agents read the config.
    async config(cfg) {
      try {
        await applyConfig(cfg, { client, options })
      } catch {} // ponytail: silent; a broken backend must never stop opencode starting
    },
  }
}

// ---- opencode v2 (2.0.18+) -------------------------------------------------
//
// v2 replaces the v1 `config(cfg)` hook with typed transforms (ctx.provider,
// ctx.mcp, ctx.skill) and moves auth from `methods: [...]` to
// `ctx.integration.transform`, registering real oauth-type methods with a
// `refresh` callback. Unlike v1, opencode itself persists credentials and
// calls `refresh` automatically (packages/core/src/integration.ts:695-698,
// verified against v2.0.18 source) whenever a resolved credential is within
// 5 minutes of `expires` — no client.auth.set() dance, no module-level
// `fresh()` needed for this path. Provider requests get their Authorization
// automatically too: a Provider.Info with `integrationID` set makes
// model-resolver.ts resolve + inject the credential as apiKey/authToken/
// accessToken depending on the SDK package (packages/core/src/model-
// resolver.ts:303-313) — this plugin never builds that header itself.
//
// All the OAuth mechanics below (discover/clientId/token/pollDevice/listen)
// are the same functions the v1 methods use above; only the registration
// shape and the config-delivery path differ.

const modality = (list) => (Array.isArray(list) && list.length ? list : ["text"])

// Wire-schema model (ackstorm.opencode-config/1) -> opencode v2 Model.Info.
// v2 has no attachment/reasoning/temperature fields (opencode normalizer logs
// them as "unsupported legacy setting" and drops them); capability now lives
// in capabilities.input/output, and cost is an array of tiers, not an object.
function toModelInfo(providerID, id, m) {
  return {
    id,
    modelID: id,
    providerID,
    name: m?.name ?? id,
    capabilities: {
      tools: !!m?.tool_call,
      input: modality(m?.modalities?.input),
      output: modality(m?.modalities?.output),
    },
    variants: [],
    time: { released: 0 },
    cost: [
      {
        input: Number(m?.cost?.input ?? 0),
        output: Number(m?.cost?.output ?? 0),
        cache: { read: Number(m?.cost?.cache_read ?? 0), write: 0 },
      },
    ],
    status: "active",
    enabled: true,
    limit: { context: Number(m?.limit?.context ?? 128000), output: Number(m?.limit?.output ?? 8192) },
  }
}

// Shared by both oauth methods: same refresh-token exchange as v1's fresh(),
// but returns the shape opencode's own resolver expects and does not persist
// anything itself (opencode does that after the callback/refresh resolves).
async function refreshCredential(methodID, credential, options) {
  const d = await discover(undefined, options)
  const client_id = await savedClientId(d.issuer)
  if (!client_id) throw new Error(`SSO client identity lost, run \`opencode auth login -p ${PROVIDER}\``)
  const t = await token(d, { grant_type: "refresh_token", refresh_token: credential.refresh, client_id }).catch((e) => {
    throw Object.assign(e, { signedOut: e.status >= 400 && e.status < 500 })
  })
  return { type: "oauth", methodID, refresh: t.refresh || credential.refresh, access: t.access, expires: t.expires }
}

async function authorizeBrowser(options) {
  const d = await discover(undefined, options)
  const verifier = b64(randomBytes(32))
  const state = b64(randomBytes(16))
  const client_id = await clientId(d)
  const { port, code } = listen(state)
  const redirect_uri = `http://127.0.0.1:${await port}/callback`
  const url = new URL(d.as.authorization_endpoint)
  url.search = new URLSearchParams({
    response_type: "code",
    client_id,
    redirect_uri,
    scope: d.scope,
    state,
    code_challenge: b64(createHash("sha256").update(verifier).digest()),
    code_challenge_method: "S256",
  })
  return {
    url: url.toString(),
    instructions: "Open the URL in your browser and sign in with your organization account.",
    mode: "auto",
    callback: (async () => {
      const t = await token(d, { grant_type: "authorization_code", code: await code, redirect_uri, client_id, code_verifier: verifier })
      return { type: "oauth", methodID: "sso-browser", refresh: t.refresh, access: t.access, expires: t.expires }
    })(),
  }
}

async function authorizeDevice(options) {
  const d = await discover(undefined, options)
  if (!d.as.device_authorization_endpoint) throw new Error("the authorization server does not offer the device grant")
  const client_id = await clientId(d)
  const da = await json(d.as.device_authorization_endpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id }),
  })
  return {
    url: da.verification_uri_complete ?? da.verification_uri,
    instructions: `Open the URL in any browser (this or another machine), confirm the code ${da.user_code} and sign in. This session completes on its own.`,
    mode: "auto",
    callback: pollDevice(d, { grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: da.device_code, client_id }, da.interval, da.expires_in).then(
      (t) => ({ type: "oauth", methodID: "sso-device", refresh: t.refresh, access: t.access, expires: t.expires }),
    ),
  }
}

// Fetches /clients/opencode/config with the resolved credential and
// registers provider+models, mcp servers and skills through the typed
// transforms. Mirrors applyConfig()'s failure handling: any error here must
// never stop opencode starting.
async function applyV2Config(ctx) {
  const active = await ctx.integration.connection.active(PROVIDER).catch(() => undefined)
  if (!active) return // signed out: nothing to deliver, same as v1
  const credential = await ctx.integration.connection.resolve(active).catch(() => undefined)
  if (credential?.type !== "oauth") return
  const { platform } = await backend(ctx.options)
  const body = await fetchConfig(platform, credential.access)
  if (!body || body.auth === "invalid") return
  const cfg = body.config ?? {}

  await ctx.provider.transform((editor) => {
    for (const [pid, p] of Object.entries(cfg.provider ?? {})) {
      const models = Object.entries(p?.models ?? {}).map(([mid, m]) => toModelInfo(pid, mid, m))
      if (!models.length) continue
      editor.add({
        info: {
          id: pid,
          name: p?.name ?? pid,
          activation: "enabled",
          // v1's wire schema carries `npm` for the v1 loader (raw @ai-sdk/openai-compatible,
          // which that loader consumes directly). v2's DynamicProviderPlugin expects a
          // `.model(modelID, settings)` factory that the vanilla published package does not
          // have at any version (opencode's own monorepo patches it in); their own built-in
          // openai-compatible-style providers (e.g. LM Studio) use this wrapper instead
          // (packages/core/src/plugin/provider/lmstudio.ts, verified against opencode 2.0.18).
          // This is v2-runtime plumbing, not server config, so it's hardcoded here rather than
          // trusting `p.npm` — verified end-to-end against a real device-grant login.
          package: "@opencode/ai/providers/openai-compatible",
          integrationID: PROVIDER,
          settings: p?.options?.baseURL ? { baseURL: p.options.baseURL } : undefined,
        },
        models,
      })
    }
  })

  await ctx.mcp.transform((editor) => {
    for (const [name, m] of Object.entries(cfg.mcp ?? {})) {
      if (m?.type !== "remote" || !m.url) continue
      editor.set(name, { type: "remote", url: m.url, disabled: m.enabled === false })
    }
  })

  if (await writeSkills(body.skills)) {
    const dir = paths().skills
    await ctx.skill.transform((editor) => {
      for (const s of Array.isArray(body.skills) ? body.skills : []) {
        const md = s?.files?.["SKILL.md"]
        if (typeof md !== "string") continue
        editor.add({ id: s.name, name: s.name, path: `${dir}/${s.name}/SKILL.md`, content: md })
      }
    })
  }
}

// One file, both engines: opencode v1 reads `server` (it rejects a default export
// with an id but no server()); v2 reads `setup`.
export default {
  id: "oidc-provider",
  server: SsoAuth,
  async setup(ctx) {
    const { provider } = await backend(ctx.options)
    if (PROVIDER_ID.test(provider ?? "")) PROVIDER = provider

    await ctx.integration.transform((editor) => {
      editor.update(PROVIDER, (integration) => {
        integration.name = PROVIDER
      })
      editor.method.update({
        integrationID: PROVIDER,
        method: { id: "sso-browser", type: "oauth", label: "SSO (browser)" },
        authorize: () => authorizeBrowser(ctx.options),
        refresh: (credential) => refreshCredential("sso-browser", credential, ctx.options),
      })
      editor.method.update({
        integrationID: PROVIDER,
        method: { id: "sso-device", type: "oauth", label: "SSO (device code — sign in from another browser)" },
        authorize: () => authorizeDevice(ctx.options),
        refresh: (credential) => refreshCredential("sso-device", credential, ctx.options),
      })
    })

    try {
      await applyV2Config(ctx)
    } catch {} // ponytail: silent; a broken backend must never stop opencode starting
  },
}
