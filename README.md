# Backblaze Restore App: "Unavailable" chunk bug + a Frida-based fix

A reproducible bug in Backblaze Personal Backup's Windows Restore App
(`bzrestore.exe`) that permanently gives up on chunks of a file mid-restore,
marking them "Unavailable" and never recovering that file's content — even
though the data is often still genuinely retrievable. This repo has the
write-up plus a Frida script that patches the behavior live, in memory,
without touching the app's files on disk.

**This is an unofficial, third-party workaround, not something from
Backblaze.** Use at your own risk, read the whole README first, and see
[Disclaimer](#disclaimer) below.

## The bug

When restoring a file, `bzrestore.exe` splits it into 10MB chunks
(`fguid`s) and requests them in batches from
`POST /api/download_b1_files_from_vault`. The response is a ZIP stream
containing the successfully-retrieved chunks plus a `response.json`
manifest with a per-chunk status object, including a `code` field.

Two values of `code` matter here:

- `"retry"` → the client marks that chunk `NeedsDownload` and will
  automatically retry it later in the same session.
- `"unavailable"` → the client marks that chunk `Unavailable` — a
  **terminal** state. It is never retried again for the rest of that
  restore session.

The problem: chunks marked `"unavailable"` are frequently **not actually
gone**. Confirmed repeatedly:

- The exact same file, restored via backblaze.com's website instead of the
  desktop app, downloaded completely fine after the desktop app had marked
  it Unavailable and given up 3+ times.
- Chunks the desktop app itself marked `Unavailable` in one session were
  seen to download successfully in a later, independent restore attempt of
  the same file.
- The client already has a working "keep trying" mechanism (the
  `"retry"` → `NeedsDownload` path) — `unavailable` just isn't routed into
  it.

So the fix is conceptually simple: make `unavailable` behave exactly like
`retry`.

## The fix

`bz_unavailable_patch.js` is a [Frida](https://frida.re/) script that
hooks a small, generic string-assignment helper inside `bzrestore.exe`
(confirmed at a fixed address for v10.0.3.1075 — see
[Gotchas](#gotchas-if-youre-adapting-this) if your version differs) and
intercepts the exact moment a chunk's state is about to be written as
`"Unavailable"`. When that happens, it rewrites the value in memory to
`"NeedsDownload"` instead, before the original function call proceeds —
so the client's own existing retry logic picks it up and keeps trying,
rather than ever writing the chunk off for good.

It's a pure runtime memory patch:

- Never modifies `bzrestore.exe` on disk.
- Must be reattached every time the process is (re)launched (see
  `bz_watch_and_hook.ps1` for automating that).
- Filters on *both* the string content and the exact call site (return
  address) it's called from — this generic helper function is shared by
  ~20+ unrelated call sites in the binary (including, it turns out, a
  periodic UI/bookkeeping refresh loop that repeatedly re-touches
  already-known-bad chunks). An earlier, less careful version that
  filtered on content alone fired 5000+ times per session and appeared to
  destabilize the app's internal progress counters when applied live. See
  the comments in the script for the exact addresses used.

In testing, this converted several restore sessions that previously ended
with files permanently marked `Unavailable` (after 3+ separate attempts
each) into 100%-successful restores, including a 53.74GB 2160p remux that
had failed on every previous attempt.

## How it was found (summary)

- Captured the actual HTTPS traffic between `bzrestore.exe` and
  Backblaze's API by hooking `secur32.dll`'s `EncryptMessage`/
  `DecryptMessage` inside the running process with Frida (the app is
  libcurl+schannel with its own embedded CA bundle, so a normal MITM
  proxy doesn't work against it).
- That traffic capture showed the client parsing a `code` field per-chunk
  from `response.json`, and showed failed chunks receiving clean `200 OK`
  responses — ruling out a simple network/timeout explanation.
- Loaded `bzrestore.exe` in Ghidra and searched for the (uniquely
  identifiable, actually-misspelled-by-Backblaze) log string
  `"Unavailble chunk: %ju bytes, fguid %s"`, then traced its
  cross-references back to the function handling per-chunk responses,
  and read the decompiled logic for the `retry`/`unavailable` branch.
- Confirmed the target function and call site with Frida before writing
  the fix, by dumping raw bytes at the computed address and comparing
  them to the expected instruction prologue.

## Usage

Requires [Frida](https://frida.re/) (`pip install frida-tools`) and an
elevated terminal (Frida's process-attach needs `SeDebugPrivilege`, even
for your own processes).

1. **Start in dry-run mode.** `DRY_RUN = true` is the default in the
   script — it only logs when it would act, without changing anything.
   Run:
   ```
   frida -n bzrestore.exe -l bz_unavailable_patch.js
   ```
   Confirm it fires a *sane* number of times (roughly once per genuine
   chunk failure, not thousands) before trusting it.
2. **Flip to live.** Edit the script, set `DRY_RUN = false`, and reattach
   the same way. Retry whatever restore previously got stuck.
3. **(Optional) Automate reattachment.** `bz_watch_and_hook.ps1` polls for
   `bzrestore.exe` and automatically spawns a fresh hook every time the
   app (re)starts, so you don't have to manually reattach after every
   restart/crash/relaunch.

## Gotchas if you're adapting this

- **Verify which copy of `bzrestore.exe` is actually running before doing
  anything else.** If you have more than one Backblaze install on your
  system (e.g. an old one left over from a previous setup), the
  addresses in this script will silently point at the wrong code with no
  error — Frida will happily attach and do nothing, or worse. The script
  logs `Process.getModuleByName(...).path` on startup specifically so you
  can catch this immediately; don't skip checking it.
- **Addresses are build-specific.** If Backblaze has shipped a newer
  version than v10.0.3.1075, the static addresses in this script will be
  wrong. To re-derive them: open the running `bzrestore.exe` in Ghidra,
  search all strings for the literal (and, delightfully, still-misspelled
  as of this writing) text `Unavailble chunk`, find its cross-reference,
  trace into the containing function, and look for a call passing the
  literal string `"Unavailable"` with length `0xb` — that call's target
  is the helper to hook, and the call instruction's own address (+5, for
  the call's own length) is the return-address filter to use.

## Disclaimer

This is provided as-is, for personal, educational, and interoperability
purposes — recovering your own data from your own paid backup. It:

- Only modifies your own local process's memory at runtime, never
  Backblaze's servers, other users' data, or the app's files on disk.
- Comes with no warranty. Test on a small/low-stakes restore first.
  Reverse engineering always carries some risk of unexpected behavior.
- Is not affiliated with or endorsed by Backblaze.
