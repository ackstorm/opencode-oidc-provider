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
  journal: `${DATA}/${PROVIDER}/rotation.json`, // latest exchange: the cross-process race breaker
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
// metadata (RFC 8414). Cached per process for refreshes; a login passes
// fresh=true, because a long-lived process (v2's background service) would
// otherwise keep a moved authorization server until it restarts.
let discovered
function discover(client, options, fresh = false) {
  if (fresh) discovered = undefined
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

// The newest tokens this machine exchanged, both engines, every exchange: the
// cross-process race breaker. opencode shares one credential across processes,
// each with its own view of the store, and the AS invalidates a refresh token
// the moment it rotates it — so a process that refreshes with a token another
// process has already spent gets a 4xx and the turn is lost. The loser adopts
// the winner's tokens from here instead. It duplicates secrets on disk (0600,
// like every file in this folder, and opencode's own store) and only ever
// adopts tokens of the same user (JWT sub) that are still valid for over 60 s.
const JOURNAL_POLL = Number(process.env.OIDC_JOURNAL_POLL_MS ?? 250)
const JOURNAL_GRACE = Number(process.env.OIDC_JOURNAL_GRACE_MS ?? 2_500) // the loser's 4xx crosses the winner's write
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

async function journalWrite(t, previous) {
  try {
    await writePrivate(paths().journal, JSON.stringify({ user: sub(t.access), previous, refresh: t.refresh, access: t.access, expires: t.expires, at: Date.now() }))
  } catch {} // best effort: without it the rescue degrades to "session expired"
}

const adoptable = (j, user) => typeof j?.refresh === "string" && user != null && j.user === user && j.expires > Date.now() + 60_000

// What replaced `spent`: the winner writes the journal right after its exchange
// answers, so a loser whose 4xx arrived first polls briefly before giving up.
// null = nothing replaced it, the session is really over.
async function rescue(user, spent) {
  for (let waited = 0; ; waited += JOURNAL_POLL) {
    const j = await readJson(paths().journal)
    if (adoptable(j, user) && j.refresh !== spent) return { access: j.access, refresh: j.refresh, expires: j.expires }
    if (waited >= JOURNAL_GRACE) return null
    await sleep(JOURNAL_POLL)
  }
}

// One refresh-token exchange, shared by both engines. A 4xx may only mean that
// another process spent this refresh token first: adopt the winner's tokens
// before declaring the session over. A 5xx keeps its error: an outage is not
// a sign-out.
async function rotate(d, client_id, again, user) {
  let t
  try {
    t = await token(d, { grant_type: "refresh_token", refresh_token: again.refresh, client_id })
  } catch (e) {
    console.warn(`[${PROVIDER}] token refresh failed: ${e.message}`)
    if (e.status < 400 || e.status >= 500) throw e
    t = await rescue(user, again.refresh)
    if (!t) throw new Error(`${PROVIDER} session expired, run \`opencode auth login ${PROVIDER}\``)
  }
  await journalWrite(t, again.refresh) // for an adopted token too: harmless, keeps `at` fresh
  return t
}

// One in-flight refresh per process, shared by loader.fetch and the config hook.
// A race across processes no longer spends a rotated token: the journal lets the
// loser adopt the winner's instead.
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
    // The store can lag a rotation by another process, which invalidated the
    // spent refresh token: the journal holds its successor — adopt it instead
    // of spending the token again.
    const j = await readJson(paths().journal)
    const t = {
      type: "oauth",
      ...(adoptable(j, sub(again?.access)) && j.previous === again.refresh
        ? { access: j.access, refresh: j.refresh, expires: j.expires }
        // Only the token endpoint's 4xx means "signed out"; a 4xx from discovery
        // (a misrouted .well-known) is an outage, not a revoked session.
        : await rotate(d, client_id, again, sub(again?.access))),
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

// The config hook. Signed out → nothing (not even the cache). Backend down or
// refresh token rejected → the same user's cache if < 30 d, so the provider
// stays listed and a chat shows fresh()'s "run opencode auth login". Never
// throws; errors mean "no backend config".
async function applyConfig(cfg, { client, options }) {
  const getAuth = async () => (await readJson(AUTH_FILE))?.[PROVIDER]
  const stored = await getAuth()
  if (stored?.type !== "oauth") return
  const forget = () => rm(paths().cache, { force: true })
  // An expired access token would read as "invalid" at the backend, so a failed refresh uses the cache.
  const auth = await fresh(stored, { client, options, getAuth }).catch(() => null)
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
            const d = await discover(client, options, true)
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
                  await journalWrite(t, null) // a login replaces tokens; nothing was rotated
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
            const d = await discover(client, options, true)
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
                  await journalWrite(t, null) // a login replaces tokens; nothing was rotated
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
// `reasoning` becomes the low/medium/high variants v1 generated itself — the
// same ones v2's Variant.resolve gives openai-compatible (core/src/variant.ts:76-79).
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
    variants: m?.reasoning ? ["low", "medium", "high"].map((id) => ({ id, settings: { reasoningEffort: id } })) : [],
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
// Every location resolves the credential at once (login, restart) and the AS
// rotates refresh tokens, so callers holding the same token share one exchange.
const refreshes = new Map()
function refreshCredential(methodID, credential, options) {
  const key = credential.refresh
  if (!refreshes.has(key)) refreshes.set(key, (async () => {
    // The credential this process was handed may lag a rotation by another
    // process, which invalidated the spent refresh token: the journal holds
    // its successor — adopt it instead of spending the token again.
    const j = await readJson(paths().journal)
    if (adoptable(j, sub(credential.access)) && j.previous === credential.refresh) {
      return { type: "oauth", methodID, refresh: j.refresh, access: j.access, expires: j.expires }
    }
    return exchange(methodID, credential, options)
  })().finally(() => refreshes.delete(key)))
  return refreshes.get(key)
}

async function exchange(methodID, credential, options) {
  const d = await discover(undefined, options)
  const client_id = await savedClientId(d.issuer)
  if (!client_id) throw new Error(`SSO client identity lost, run \`opencode auth login -p ${PROVIDER}\``)
  const t = await rotate(d, client_id, credential, sub(credential.access))
  return { type: "oauth", methodID, refresh: t.refresh || credential.refresh, access: t.access, expires: t.expires }
}

async function authorizeBrowser(options) {
  const d = await discover(undefined, options, true)
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
      await journalWrite(t, null) // a login replaces tokens; nothing was rotated
      return { type: "oauth", methodID: "sso-browser", refresh: t.refresh, access: t.access, expires: t.expires }
    })(),
  }
}

async function authorizeDevice(options) {
  const d = await discover(undefined, options, true)
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
    callback: pollDevice(d, { grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: da.device_code, client_id }, da.interval, da.expires_in).then(async (t) => {
      await journalWrite(t, null) // a login replaces tokens; nothing was rotated
      return { type: "oauth", methodID: "sso-device", refresh: t.refresh, access: t.access, expires: t.expires }
    }),
  }
}

// Fetches /clients/opencode/config with the resolved credential. Mirrors
// applyConfig()'s failure handling: never throws, null means "nothing to deliver".
// A credential that no longer resolves (dead refresh token) or a backend that
// is down falls back to the last cached body (< 30 d), so the provider stays
// listed and a chat shows refreshCredential()'s "run opencode auth login".
async function loadV2Config(ctx) {
  try {
    const active = await ctx.integration.connection.active(PROVIDER).catch(() => undefined)
    if (!active) return null // signed out: nothing to deliver, same as v1
    const credential = await ctx.integration.connection.resolve(active).catch((e) => {
      console.warn(`[${PROVIDER}] credential did not resolve: ${e?.message ?? e}`)
    })
    const { platform } = await backend(ctx.options)
    const body = credential?.type === "oauth" ? await fetchConfig(platform, credential.access) : null
    if (body?.auth === "invalid") return null
    if (body) {
      await writePrivate(paths().cache, JSON.stringify({ user: body.user, fetchedAt: Date.now(), body }))
      await writeSkills(body.skills)
      return body
    }
    console.warn(`[${PROVIDER}] no config from ${platform}, using the cached one`)
    const cache = await readJson(paths().cache)
    return cache && Date.now() - cache.fetchedAt <= CACHE_MAX_AGE ? cache.body : null
  } catch {
    return null
  }
}

// v2 takes a skill as given and never reads its frontmatter: one without a
// description is left out of the model's skill list and shown blank in /skills.
// ponytail: single-line `description:` only (what our backends send); a YAML
// parser if one ever sends a folded/multi-line value.
function skillDescription(md) {
  const front = md.match(/^---\r?\n([\s\S]*?)\r?\n---/)?.[1] ?? ""
  return front.match(/^description:[ \t]*(.+?)[ \t]*$/m)?.[1].replace(/^(["'])(.*)\1$/, "$2")
}

// Registers provider+models, mcp servers and skills through the typed
// transforms, once; each run reads `state.delivered`.
async function registerV2Transforms(ctx, state) {
  await ctx.provider.transform((editor) => {
    for (const [pid, p] of Object.entries(state.delivered?.config?.provider ?? {})) {
      // A throwing transform disables the whole plugin, login included: skip the entry instead.
      try {
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
      } catch {}
    }
  })

  await ctx.mcp.transform((editor) => {
    for (const [name, m] of Object.entries(state.delivered?.config?.mcp ?? {})) {
      if (m?.type !== "remote" || !m.url) continue
      try {
        editor.set(name, { type: "remote", url: m.url, disabled: m.enabled === false })
      } catch {}
    }
  })

  await ctx.skill.transform((editor) => {
    const dir = paths().skills
    for (const s of Array.isArray(state.delivered?.skills) ? state.delivered.skills : []) {
      const md = s?.files?.["SKILL.md"]
      if (typeof s?.name !== "string" || !SKILL_NAME.test(s.name) || typeof md !== "string") continue
      try {
        editor.add({ id: s.name, name: s.name, description: skillDescription(md), path: `${dir}/${s.name}/SKILL.md`, content: md })
      } catch {}
    }
  })
}

// v2's background service outlives `opencode auth login`: the credential lands
// in this process (credential.switched, core/src/credential.ts), so re-fetch
// and reload instead of waiting for a restart. Never awaited; runs until unload.
async function watchLogin(ctx, state) {
  try {
    for await (const e of ctx.event.subscribe()) {
      if (e?.type !== "credential.switched" || e.data?.integrationID !== PROVIDER) continue
      try {
        state.delivered = await loadV2Config(ctx)
        await Promise.all([ctx.provider.reload(), ctx.mcp.reload(), ctx.skill.reload()])
      } catch {} // one failed reload must not end the watch: the next login retries
    }
  } catch {} // ponytail: silent; worst case is the old behaviour (restart to pick up a login)
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

    // Last good /clients/opencode/config body for this location's credential, or
    // null. Per setup(): the service runs it once per location in one module
    // instance, so a module-level value let one location's empty load drop the
    // provider everywhere at the next reload.
    const state = { delivered: await loadV2Config(ctx) }
    try {
      await registerV2Transforms(ctx, state)
    } catch {} // ponytail: silent; a broken backend must never stop opencode starting
    watchLogin(ctx, state)
  },
}
