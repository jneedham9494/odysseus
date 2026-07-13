# PWA install + iOS Shortcuts share-sheet capture (MR-23)

Odysseus ships a web app manifest and a service worker so the web UI can be
**installed** to a phone / desktop home screen and opened like a native app,
plus an owner-authenticated **capture** endpoint you can drive from the OS share
sheet (Android) or an **iOS Shortcut** to file text / links / files straight
into your Notes.

## 1. Install the app

Open the site in a browser and choose **Add to Home Screen** (iOS Safari) or
**Install app** (Android Chrome / desktop Chrome). This is powered by:

- `GET /manifest.json` — served with `application/manifest+json`.
- `GET /sw.js` — served with `text/javascript` and `Service-Worker-Allowed: /`
  so the service worker controls the whole origin (offline app shell).

Both also exist under `/static/`; the root copies exist so the service worker
can claim root scope and both carry their canonical content-types.

## 2. Enable capture (off by default)

The capture endpoint is an internet-facing entry point, so it ships **disabled**.
Turn it on with either:

- Env var: `PWA_CAPTURE_ENABLED=true`, **or**
- Setting: `pwa_capture_enabled: true` in the app settings.

While disabled, `POST /api/capture` returns `404` and reveals nothing.

## 3. Authentication (owner-only)

`POST /api/capture` accepts **only** an authenticated owner:

- **Cookie session** — used automatically by the Android Web Share Target when
  you share into the installed PWA while logged in.
- **Bearer API token** — for iOS Shortcuts / any HTTP client. Mint one in the
  app (API tokens) with a write scope. A **`todos:write`** (or `memory:write`)
  token is sufficient; the "codex_todos" profile grants it. Unscoped tokens are
  also accepted (owner proof alone).

Anonymous callers get `401`. A scoped token lacking a write scope gets `403`.
The captured note is filed under the **token's owner**, so it shows up in the
same Notes your browser sees — not a separate `api` silo.

### Security model

Shared text/URLs are treated as **untrusted external content**. The stored note
is tagged `source="capture"` so any later agent ingestion inherits the existing
taint model. Capture itself only performs a benign local write (create a note)
and triggers no credentialed real-world action, so — unlike autonomous agent
actions — it is not routed through the approval queue: the human owner is
directly and explicitly authoring the note.

## 4. Request format

`POST /api/capture` accepts **JSON** or **form / multipart** bodies with any of:

| field   | meaning                                  |
|---------|------------------------------------------|
| `title` | optional note title                      |
| `text`  | shared text / selection / note body      |
| `url`   | shared link (must be `http(s)`; others dropped) |
| `files` | optional file uploads (multipart only)   |

At least one of `title` / `text` / `url` / a file is required (else `422`).

JSON example:

```bash
curl -X POST https://YOUR_HOST/api/capture \
  -H "Authorization: Bearer ody_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"Read later","text":"great article","url":"https://example.com/a"}'
# -> 201 {"ok": true, "id": "<note-uuid>"}
```

## 5. iOS Shortcut recipe

Create a Shortcut named **"Send to Odysseus"** and enable **Show in Share Sheet**
(Shortcut Details), accepting **Text**, **URLs**, and **Safari web pages**.

Actions:

1. **Receive** *Text, URLs, Safari web pages* input from the Share Sheet.
2. **Text** action = the received **Shortcut Input** (this becomes `text`).
3. **Get Contents of URL**:
   - **URL**: `https://YOUR_HOST/api/capture`
   - **Method**: `POST`
   - **Headers**:
     - `Authorization` = `Bearer ody_YOUR_TOKEN`
   - **Request Body**: `JSON`
     - `title` (Text) = e.g. `Shared from iOS`
     - `text`  (Text) = the **Text** variable from step 2
     - `url`   (Text) = the **Shortcut Input** (when sharing a link)
4. (Optional) **Show Notification** with the response so you get a confirmation.

Store the token in the Shortcut once; iOS keeps it on-device. Rotate it in the
app's API-token screen if the phone is lost — that immediately revokes capture.

### Files

To share a file (PDF, image, screenshot), use **Request Body: Form**, add a
field named `files`, and set it to the shared file. Text files are folded into
the note body; binaries are recorded by name. The endpoint accepts up to 10
files, 1 MB read per file.

## 6. Android / desktop Web Share Target

The manifest declares a `share_target` pointing at `/api/capture`
(`multipart/form-data`, params `title` / `text` / `url` / `files`). After
installing the PWA, "Share" from any app lists **Odysseus** as a target; sharing
posts to the same endpoint using your logged-in session and lands you on
`/notes`.
