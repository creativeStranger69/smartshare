# SmartShare - Duplicate-Free Media Group Chat

Real-time group chat (Node.js, Express, Socket.io, MongoDB) that **detects duplicate uploads by SHA-256 hash**
and replaces them with a "System Alert" pointing to the original file. Includes a per-group media gallery and a
storage-savings dashboard.

## Quick start (development)

```bash
npm install
cp .env.example .env        # Windows: copy .env.example .env   (then edit MONGO_URI if needed)
npm start                   # http://localhost:3000
```
MongoDB must be running (local install) or `MONGO_URI` must point to MongoDB Atlas.

| Command | What it does |
|---|---|
| `npm start` | run the server |
| `npm run dev` | run with auto-restart on file changes |
| `npm test` | unit tests (validation, file-serving safety, deduplication engine). No database needed |
| `npm run smoke` | end-to-end check against a **running** server (register, upload twice, dedup, permissions, paging) |

## Deploy (production)

**Option A - Docker (recommended)**
```bash
echo "JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(48).toString('hex'))")" > .env
docker compose up -d --build          # app + MongoDB + persistent volumes
```
Put an HTTPS reverse proxy in front. With Caddy this is the whole config:
```
chat.yourdomain.com {
    reverse_proxy 127.0.0.1:3000
}
```
(For nginx, forward `Host`, `X-Forwarded-For`, `X-Forwarded-Proto` and enable WebSocket upgrade headers.)
Cookies are `Secure` in production, so the site must be served over HTTPS (or set `COOKIE_SECURE=false` for a local test only).

**Option B - plain Node on a VPS / Render / Railway**: set `NODE_ENV=production`, `MONGO_URI` (Atlas), `JWT_SECRET` (32+ chars),
run `npm start`, and keep `uploads/` on a persistent disk. In production the server **refuses to start** with a weak/missing secret.

**Backups:** back up the MongoDB database **and** the `uploads` volume together - the database rows point at the files.

### Deploy on Render (free)
1. Create a free MongoDB Atlas cluster and copy its connection string (add `/smartshare` as the database name; allow `0.0.0.0/0` under Network Access).
2. Push this folder to a GitHub repo (`.env` is git-ignored).
3. On render.com choose **New > Blueprint**, pick the repo (it reads `render.yaml`), paste `MONGO_URI` when asked, and deploy.
Note: the free plan's disk is temporary, so uploaded files vanish on restart - fine for a demo; use a persistent disk for real use.

## What makes it production-grade

| Area | What is implemented |
|---|---|
| Authentication | bcrypt (cost 12), JWT in an **httpOnly + SameSite=Strict (+Secure)** cookie - never in localStorage; same cookie authenticates WebSockets; constant-time login (no user enumeration) |
| Authorisation | every group route checks membership; **uploaded files are not public** - `/files/:groupId/:fileId` is membership-checked |
| Input validation | every field type-checked and length-limited (blocks NoSQL-injection objects like `{"$ne":null}`); usernames case-normalised |
| Abuse protection | rate limits on login / register / upload / API / files; per-socket message rate limit; size caps for JSON, uploads and chat text |
| HTTP hardening | helmet security headers + strict Content-Security-Policy, same-origin (CSRF) check, WebSocket origin check, `x-powered-by` removed |
| Safe file serving | content-type chosen from an extension **allow-list** (never from the uploader); HTML/SVG/JS are forced to download; `nosniff` + sandbox CSP; path traversal impossible (only a DB-held basename is used) |
| Deduplication | SHA-256, unique DB index `(groupId, hash)` so races are safe, atomic temp-file + rename writes, hash-named files shared across groups |
| Reliability | async errors always reach one error handler (no hung requests), no stack traces to clients, `/healthz`, graceful shutdown on SIGTERM, clear message if MongoDB is down |
| Scale-readiness | paged history (cursor on `_id`) with a matching index, lean queries, gzip, long-lived cache for immutable files |
| Ops | structured JSON logs, 12-factor config (`.env`), Dockerfile (non-root user, healthcheck), docker-compose with MongoDB |
| Accessibility | labelled inputs, ARIA live regions, keyboard-selectable groups, visible focus ring, reconnect banner |

### Honest limits (say these in the viva - they show you understand the design)
- **One server instance.** Socket.io rooms live in memory; to run several instances add the Redis adapter. Uploads are on local disk; for several servers move them to S3/GCS (the content-addressed naming makes that easy).
- **Whole upload is held in RAM** while hashing (needed to hash *before* storing). Fine for the 25 MB limit; for huge files hash as a stream into a temp file.
- **Exact duplicates are blocked; near-duplicate images are only flagged** (perceptual hash), never rejected.
- No email verification / password reset. Everyone registered can see every other username in the picker (fine for a campus/team app; add invitations or a directory opt-out for a public service). Deleted messages stay as tombstones, and a deleted file is removed only for the group that deleted it.

## v4 features

| Feature | How it works |
|---|---|
| **New login / register design** | Dark-violet split card: artwork + rotating highlights on the left; show/hide password, live password-strength bar, language picker on the form. Fully responsive (phone = single column). |
| **One-to-one chats** | 💬 button -> pick anyone registered. A direct chat is a `Group` with `isDirect: true` and exactly 2 members, so dedup, gallery, link check, translation and edit/delete work in it unchanged. A unique `directKey` (the two user ids sorted) means only ONE chat per pair, even if both press "chat" at the same moment. Each person sees the *other* person's name. |
| **User suggestions** | `GET /api/users?q=&groupId=` returns every registered user except you (usernames only, never emails), searchable; used by New chat, New group and Add members. People already in the group are greyed out. |
| **Edit / delete for everyone** | Edit: own text messages, within 15 minutes, links are re-checked and translations redone, shown as "edited". Delete: own messages; the row becomes a tombstone. Deleting a file message removes it from the gallery and **reference-counts** the stored file: the bytes leave the disk only when no other group still uses the same hash (`lib/chats.js`). The same file can be shared again afterwards. |

## v3 features

| Feature | How it works | Setup |
|---|---|---|
| **Duplicate file + similar image** | Exact copies: SHA-256 -> System Alert, nothing stored twice. Re-compressed / resized images: perceptual hash (dHash, Hamming distance, >=90% = "looks N% similar", file is still kept) | `sharp` (optional dependency; without it only exact matching runs) |
| **Fraud-link check** | Every link gets a risk score (0-100%) from heuristics: IP-address host, `@` trick, look-alike / punycode domains, brand impersonation, URL shorteners, suspicious TLDs, scam words, executables. Links are never real `<a href>`; clicking opens a dialog with the verdict, percent, reasons, and (for dangerous links) a tick-box permission before "Open anyway". Optional Google Safe Browsing lookup adds known-malware / phishing detection | `SAFE_BROWSING_API_KEY` (optional) |
| **Auto-translate chat** | Each user picks a reading language. A new message is translated once per language and pushed to every member's own language; "Show original" toggle and a manual Translate button. Links inside text are never translated | `TRANSLATE_PROVIDER` (default `mymemory`, free, no key) |

### Limits of the v3 features (be upfront about these)
- **A "Safe" badge is not a guarantee.** Heuristics only estimate risk; a brand-new phishing site on a clean-looking domain can score low. Safe Browsing improves this but is not perfect either.
- **Similar-image detection** does not match crops or rotations, and flat/blank images are skipped.
- **Translation sends message text to the provider** (MyMemory by default, free quota about 5,000 characters/day; set `MYMEMORY_EMAIL` for more). Use `TRANSLATE_PROVIDER=libretranslate` (self-hosted) for privacy, or `none` to disable. Language is detected by script, so Roman Urdu / Hinglish (Urdu written in English letters) cannot be detected. Translations are machine quality.
- Sockets are in memory, so translation push works for a single server instance.

## Project map

| File | Role |
|---|---|
| `server.js` | Express routes, Socket.io, security middleware, startup/shutdown |
| `dedup.js` | **Core engine**: `sha256()`, `processUpload()`, `dedupMiddleware` |
| `config.js` | all settings from environment + production safety checks |
| `models/index.js` | 4 Mongoose schemas: User, Group, Message, FileHash |
| `lib/auth.js · validate.js · files.js · logger.js` | cookies/JWT, input validation, safe file serving, logging |
| `lib/chats.js` | direct-chat key, user-search filter, edit rules, file reference counting |
| `lib/phash.js · links.js · linkRisk.js` | similar-image hash, link extraction, fraud-link scoring |
| `lib/translate.js · langdetect.js · languages.js · messageView.js` | translation providers, language detection, per-viewer message view |
| `public/` | `index.html`, `style.css`, `app.js` - split-screen client (vanilla JS) |
| `test/` · `scripts/smoke.js` | automated tests |
| `Dockerfile · docker-compose.yml · .env.example` | deployment |

## Data flow of a file upload

```
Browser --POST multipart--> rate limit -> auth cookie -> membership check -> multer (RAM)
   -> dedupMiddleware: sha256(bytes) -> FileHash.findOne({groupId, hash})
        found  -> NO disk write -> Message{isMedia:false, mediaRef:<old FileHash id>, "System Alert..."}
        absent -> write uploads/<hash>.ext (atomic) -> FileHash.create -> Message{isMedia:true, mediaRef:<new id>}
   -> io.to("group:<id>").emit("newMessage")  --WebSocket--> all members' browsers render a bubble
Download:  GET /files/<group>/<fileId> -> auth -> membership -> DB row -> allow-listed content-type -> bytes
```

## Likely viva questions

1. **Why hash content instead of comparing file names?** Names/sizes can match for different files and differ for identical ones; the hash depends only on the bytes.
2. **Why SHA-256 rather than MD5?** MD5 has practical collision attacks (two different files, same hash). SHA-256 has none, and Node's `crypto` makes it just as easy.
3. **Two people upload the same file at the same moment?** Both pass the `findOne` check, but the unique index on `(groupId, fileHashString)` rejects the second insert (error 11000); `dedup.js` catches it and treats it as a duplicate. (There is a test for exactly this.)
4. **Why is dedup scoped per group?** Requirement: a file in group A may still be shared in group B. Disk is still saved because files are named by hash.
5. **Why an httpOnly cookie instead of localStorage?** JavaScript cannot read it, so an XSS bug cannot steal the session; SameSite=Strict stops other sites from using it (CSRF).
6. **What is NoSQL injection and how is it blocked?** A client sends `{"$ne":null}` instead of a string so a query matches everyone. Every field is forced to a string before it reaches Mongoose (`lib/validate.js`).
7. **Why not serve `/uploads` statically?** Anyone with the URL could read any group's files. Files go through a membership-checked route, and their content-type comes from an allow-list so an uploaded `.html` can never run scripts on our domain.
8. **Why multer memory storage?** The hash must be computed before anything is written. Trade-off and the streaming alternative are listed under "Honest limits".
9. **How would you scale it?** Redis adapter for Socket.io, S3 for files, MongoDB replica set, several app instances behind a load balancer.


## v5: install it like an app (PWA)

SmartShare is now an installable web app (Progressive Web App): it gets its own icon, opens full-screen without the browser bar,
and starts from the phone's home screen like WhatsApp.

| Piece | File | What it does |
|---|---|---|
| App description | `public/manifest.webmanifest` | name, colours, icons, `display: standalone` |
| Icons | `public/icon-192.png`, `icon-512.png`, `icon-maskable-512.png`, `apple-touch-icon.png` | home-screen icons (maskable = fits any round/square Android shape) |
| Service worker | `public/sw.js` | caches only the app shell (page, css, js, icons); **never** caches `/api`, `/files`, `/upload` or socket.io |
| Install button | end of `public/app.js` | shows "Install app" when the browser says the site is installable |

**How to install (the site must be served over HTTPS, e.g. your Render link; `localhost` also works for testing)**
- **Android (Chrome):** open the link, tap the **Install app** button (or menu > *Install app* / *Add to Home screen*).
- **iPhone (Safari):** tap **Share > Add to Home Screen**.
- **Windows / Mac (Chrome or Edge):** click the install icon at the right end of the address bar.

Limits (say these in the viva): this is a web app in an app wrapper, not a native Android/iOS build; it needs internet for chat
(offline it only opens the shell); push notifications while the app is closed are not implemented.
For a real `.apk` you can feed the deployed HTTPS link to PWABuilder or Bubblewrap (Trusted Web Activity), which wraps this same site.
