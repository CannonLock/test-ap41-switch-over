# AP41: moving to the Origin's per-namespace embedded issuer

Tested in a private Pelican federation built from the published v26.0 images (Registry, Director, AP41's Origin on
XRootD, a Cache), starting from AP41's real configuration. See [The test federation](#the-test-federation).

**The steps to follow are in [Transition guide](#transition-guide).** The sections before it explain why the steps
are what they are.

## Where we start

AP41's Origin today, from its running config (only the values that matter here; the storage path is a placeholder):

```yaml
Server:
  Hostname: ap41.uw.osg-htc.org
  ExternalWebUrl: https://ap41.uw.osg-htc.org:8444
  IssuerUrl: https://ap41.uw.osg-htc.org:8444
Federation:
  DiscoveryUrl: https://osg-htc.org
Origin:
  StorageType: posix
  EnableIssuer: false
  IssuerMode: embedded
  Exports:
    - FederationPrefix: /ospool/ap41/
      StoragePrefix: /storage/ap41/
      Capabilities: [DirectReads, Writes, Reads, Listings]
```

- **Trust today:** the one export names no issuers, so it inherits `Server.IssuerUrl`. That's the Origin's own URL,
  so `/ospool/ap41` trusts tokens with `iss=https://ap41.uw.osg-htc.org:8444`.
- **Who mints tokens:** only the AP.
- **Where the keys come from:** XRootD and caches find that issuer's keys at
  `https://ap41.uw.osg-htc.org:8444/.well-known/issuer.jwks`, the Origin's own signing keys from
  `IssuerKeysDirectory` (`Server.IssuerJwks` is empty).
- **What that implies:** for the AP's tokens to verify today, the AP must sign with a key in that directory. The
  simulation is built that way. Confirm it before starting (step 0).

## Where we end

`/ospool/ap41` trusts one issuer, its own per-namespace embedded issuer:
`https://ap41.uw.osg-htc.org:8444/api/v1.0/issuer/ns/ospool/ap41`.

- **Keys:** the issuer publishes the Origin's signing keys, which already include the AP's key.
- **Tokens:** the AP mints its tokens with that `iss`, signed with the same key as today.

## What the tests found

1. **Turning on the embedded issuer by itself is an outage** (stage 1a).
   - **What happens:** with `EnableIssuer: true` and no `IssuerUrls` on the export, Pelican replaces the inherited
     `https://ap41.uw.osg-htc.org:8444` with the per-namespace issuer. The Director, the Origin's XRootD and the
     Cache's XRootD all switch, and every existing AP token is refused at the Origin and through the Cache.
   - **What to do:** name the current issuer on the export in the same change (stage 1b).
2. **With AP41's trailing slash, the default embedded issuer accepts no token at all** (stages 1a and 4b). There
   are two separate problems:
   - **Spelling mismatch.** For `FederationPrefix: /ospool/ap41/`, Pelican advertises and trusts
     `.../issuer/ns/ospool/ap41/` (with the slash), but the issuer names itself `.../issuer/ns/ospool/ap41`.
   - **The slash spelling fails too.** A token carrying the slash spelling is also refused, because XRootD looks up
     `.../ns/ospool/ap41//.well-known/openid-configuration`, which is a 404.
   - **What to do:** always write `IssuerUrls` explicitly, without the trailing slash.
3. **The AP's key needs no extra publishing.** The per-namespace issuer always publishes the Origin's own signing
   keys, and the AP's key is one of them. From stage 1b on, the issuer's JWKS held exactly the AP key.
4. **The AP only has to change its issuer URL.** It keeps the same key. With both issuers trusted (stage 2), tokens
   with either `iss` work at the Origin and through the Cache.
5. **At the end, tokens whose `iss` is the Origin's own URL are no longer accepted for `/ospool/ap41`** (stages 4a
   and 4c). That separates the AP's data tokens from anything else the Origin signs under its own URL.
   - **Monitoring is separate:** the Origin still trusts its own URL for its built-in `/pelican/monitoring`
     self-tests. Today XRootD merges that into the same issuer section as `/ospool/ap41`; afterwards it stands
     alone.
6. **`Server.IssuerUrl` can go at the end.** Stage 4c behaves exactly like 4a. Its value is the same as what Pelican
   derives when it's unset, so the Origin's own discovery document is unchanged too.
7. **The Cache behaves like the Origin.** It builds its XRootD issuer list from the Director's advertisement, and in
   every stage it accepted and refused exactly the tokens the Origin did.

## Transition guide

Keep `https://ap41.uw.osg-htc.org:8444/api/v1.0/issuer/ns/ospool/ap41` exactly as written: no trailing slash.

### 0. Before you start

- **Version:** the Origin runs 26.0.2 or later (the version tested).
- **Signing key:** `IssuerKeysDirectory` (`/etc/pelican/issuer-keys`) persists across restarts. The Origin's
  Registry registration and the AP's tokens both depend on it.
- **Confirm the AP signs with one of the Origin's keys.** Decode an AP token's header and compare its `kid` with:

  ```sh
  curl -s https://ap41.uw.osg-htc.org:8444/.well-known/issuer.jwks | jq '[.keys[].kid]'
  ```

  If the `kid` isn't listed there, the AP's key comes from somewhere this simulation didn't model. Stop and
  re-check before continuing.

### 1. Turn on the embedded issuer, pinning today's issuer (`stages/1b-issuer-on-pinned.yaml`)

```yaml
Origin:
  EnableIssuer: true
  Exports:
    - FederationPrefix: /ospool/ap41/
      # ...
      IssuerUrls:
        - https://ap41.uw.osg-htc.org:8444
```

Then populate users, groups and collections. What's trusted is unchanged.

**Check:** the new issuer already publishes the AP's key.

```sh
curl -s https://ap41.uw.osg-htc.org:8444/api/v1.0/issuer/ns/ospool/ap41/.well-known/openid-configuration | jq '{issuer, jwks_uri}'
curl -s https://ap41.uw.osg-htc.org:8444/api/v1.0/issuer/ns/ospool/ap41/.well-known/issuer.jwks | jq '[.keys[].kid]'
```

Expect the AP token's `kid` to be in the list.

### 2. Trust both issuers, the new one first (`stages/2-both-issuers.yaml`)

```yaml
      IssuerUrls:
        - https://ap41.uw.osg-htc.org:8444/api/v1.0/issuer/ns/ospool/ap41
        - https://ap41.uw.osg-htc.org:8444
```

**Check, once the Origin has re-advertised** (one advertisement interval, 1 minute by default):

```sh
curl -sI https://<director>/ospool/ap41/<any object> | grep -i '^x-pelican-'
```

- **Expected headers:** two `X-Pelican-Authorization` lines (the new issuer, then `https://ap41.uw.osg-htc.org:8444`),
  and `X-Pelican-Token-Generation: issuer=https://ap41.uw.osg-htc.org:8444/api/v1.0/issuer/ns/ospool/ap41, ...`.
- **Caches pick this up later.** Each cache rebuilds its XRootD token config from the Director on its own schedule
  (`Xrootd.AuthRefreshInterval`, 5 minutes by default). The test restarted the Cache instead of waiting.
- **Old tokens:** confirm an existing AP token still reads through a cache.

### 3. Switch the AP's issuer to `https://ap41.uw.osg-htc.org:8444/api/v1.0/issuer/ns/ospool/ap41`

The Origin doesn't change in this step.

- **Signing key:** keep the same key.
- **Old tokens:** tokens issued before the switch keep working.
- **Check:** decode a new AP token (`iss` is the new URL, `kid` unchanged) and transfer through a cache.

### 4. Retire the old issuer (`stages/4c-server-issuer-removed.yaml`)

Once no old-`iss` token can still be in use, make two changes:

- **Remove `https://ap41.uw.osg-htc.org:8444` from the export's `IssuerUrls`.**
- **Remove `Server.IssuerUrl`.** Stage 4a, which keeps it, behaves the same, so this can be done later.

Keep `IssuerUrls` written out. Relying on the defaults (`stages/4b-defaults.yaml`) refuses every token.

## Rotating the signing key

The AP and the Origin share the key, and from step 1 on it is published in two places: the Origin's own JWKS and the
per-namespace issuer's. Both come from `IssuerKeysDirectory`, so adding or removing a key there updates both.

- **Adding a key:** add it to the directory before the AP signs with it.
- **Removing a key:** remove it only after the AP has stopped using it.
- **Which key Pelican signs with:** when the directory holds several keys, Pelican signs with the file whose name
  sorts first. That decides which key the Origin's own tokens use; it doesn't affect the AP.

## Results

`python3 -I verify.py` ran every stage on 2026-11-17, and all 90 checks passed. The images used:

| Image | Digest |
|---|---|
| origin:v26.0 | `sha256:fc3cdaddb1da9e3e1ee145663ce149d726524088c15808befeedc84f085208ea` |
| cache:v26.0 | `sha256:5bcd1085f4d33d07bdeb3d1280a789d787b0a3e011c92dc49311ecf0f3c08408` |
| director:v26.0 | `sha256:0bad7bec163cf4a0a28fae02dc55414ef0d49240bfbc6427a0cb10f6fbad64bd` |
| registry:v26.0 | `sha256:3df2cc317306d3edb1559dbd50de3193bc98c5cb151dba6fbb94623ed527a48a` |

All are Pelican 26.0.2.

Where each token can write and read at the Origin, and read through the Cache (Origin / Cache):

| Stage | Director advertises | Old AP token | New AP token | Trailing-slash `iss` | Unpublished key |
|---|---|---|---|---|---|
| 0 current | old | ok / ok | – / – | – / – | – / – |
| 1a issuer on, nothing else | ap41-embedded/ | **– / –** | **– / –** | **– / –** | – / – |
| 1b issuer on, old pinned | old | ok / ok | – / – | – / – | – / – |
| 2 both issuers | ap41-embedded, old | ok / ok | ok / ok | – / – | – / – |
| 4a old issuer dropped | ap41-embedded | – / – | ok / ok | – / – | – / – |
| 4c and `Server.IssuerUrl` removed | ap41-embedded | – / – | ok / ok | – / – | – / – |
| 4b defaults | ap41-embedded/ | – / – | **– / –** | **– / –** | – / – |

- **"old":** `https://ap41.uw.osg-htc.org:8444`, the Origin itself.
- **"ap41-embedded":** the per-namespace issuer; a trailing `/` marks the slash spelling.
- **Signing:** every token is signed with the AP key except the last column, which is signed with a key nobody
  publishes, as a control.

Each stage also checked the following, and all held:

- The Origin's own JWKS was exactly the AP key.
- From stage 1a on, the per-namespace issuer's discovery named itself without the slash, and its JWKS was exactly
  the AP key.

## The test federation

`compose.yaml` runs these containers, each from a published image:

| Container | Image | Role |
|---|---|---|
| `discovery` | origin (its Python) | Answers as `osg-htc.org` with the federation discovery document, pointing at this federation's Director and Registry. |
| `registry` | registry:v26.0 | The federation's Registry. |
| `director` | director:v26.0 | The federation's Director. |
| `origin` | origin:v26.0 | AP41's Origin, configured with `stages/<stage>.yaml`. Hostname `ap41.uw.osg-htc.org`, XRootD `posix` storage. Its `IssuerKeysDirectory` holds the simulated AP key. |
| `cache` | cache:v26.0 | A Cache. It builds its XRootD token config from the Director's advertisements. |
| `client` | origin:v26.0 | Sends the test requests (`curl`) from inside the federation. |

**Isolation and trust:**

- **Nothing reaches production.** `osg-htc.org` and `ap41.uw.osg-htc.org` are names on the compose network.
- **One test CA:** every server installs a throwaway CA as both its Pelican TLS CA and a system trust anchor.

**How a stage runs:**

1. Restart the Origin with that stage's config.
2. Wait until the Director serves that stage's advertisement.
3. Write a seed file.
4. Restart the Cache and wait until its XRootD config lists that stage's issuers.
5. Test.

**How the test differs from AP41:**

- **The federation is local.** The Director, Registry and discovery are this federation's, not the OSDF's.
- **The storage prefix is an empty temporary filesystem.**
- **`Logging.Origin.Scitokens` is `trace`** (AP41: `fatal`), so XRootD logs why it refuses a token.
- **Caches are restarted, not waited on,** to pick up a new issuer list.

**Not tested:**

- **Real AP41 tokens:** no real AP keys were used.
- **How the AP really gets its key:** assumed to be a key in the Origin's `IssuerKeysDirectory`; check it in step 0.
- **Their audience:** the test tokens use the WLCG "any" audience.
- **Logins and CLI token requests through the embedded issuer.**

## Running it

```sh
python3 -I verify.py                       # every stage, then tears down (about 10 minutes)
python3 -I verify.py 2-both-issuers        # chosen stages only
python3 -I verify.py up 2-both-issuers     # leave the federation running at a stage, to look around
python3 -I verify.py down
```

Needs docker and openssl. `.sim/` (ignored by git) holds the generated test CA, the simulated AP key, the Cache's
key, and each stage's XRootD token configs under `.sim/report/`. Delete it to start from scratch.
