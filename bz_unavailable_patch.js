/*
 * bz_unavailable_patch.js
 *
 * A live, in-memory Frida patch for a reproducible bug in Backblaze
 * Personal Backup's Windows "Restore App" (bzrestore.exe). See README.md
 * in this repo for the full writeup.
 *
 * Confirmed against: bzrestore.exe v10.0.3.1075, x64.
 * Addresses below are specific to that exact build - if Backblaze has
 * shipped a newer version, they will need to be re-derived (see README).
 *
 * THE BUG (in short): when restoring a file, the client asks Backblaze's
 * vault for each 10MB chunk. The server's response includes a per-chunk
 * status code. If that code is "retry", the client marks the chunk
 * NeedsDownload and keeps retrying automatically. If the code is
 * "unavailable", the client marks it Unavailable instead - a TERMINAL
 * state that is never retried again for the rest of that restore session -
 * even though the same chunk is very often still genuinely retrievable
 * (confirmed repeatedly: the exact same file downloaded fine via
 * backblaze.com's website restore after the desktop app gave up on it
 * multiple times, and chunks the desktop app itself had marked
 * "Unavailable" were later seen to succeed on a subsequent independent
 * restore attempt of the same file).
 *
 * THE FIX: force every "unavailable" verdict to be treated exactly like a
 * "retry" verdict, using the client's own existing (and apparently more
 * reliable) retry logic, instead of ever letting it give up permanently.
 *
 * Both state strings are written through the same generic string-assign
 * helper (matches std::string::assign(this=RCX, data=RDX, len=R8) under
 * the MS x64 calling convention). That helper is called from MANY places
 * in the binary for unrelated strings - including a periodic UI/
 * bookkeeping refresh path that keeps re-touching already-known-bad
 * chunks. Filtering on string content alone fires thousands of times per
 * session purely from that refresh loop re-asserting already-terminal
 * chunks - which, once live-patching, appeared to corrupt the app's
 * internal remaining-chunk counters (observed a "18446744073709551615
 * files" unsigned-underflow in the live UI). So this script filters on
 * the CALLER too, not just content - see the Gotchas section in README.md
 * for how to re-derive the addresses for a different build.
 *
 * IMPORTANT SAFETY NOTES:
 * - This never modifies bzrestore.exe on disk. It's a runtime memory patch
 *   only, and must be re-applied every time the process is (re)launched.
 * - Start with DRY_RUN = true and confirm it fires a SANE number of times
 *   (roughly once per genuine failed chunk, not thousands) before
 *   flipping to false.
 * - Test on a small/low-stakes restore before trusting it with anything
 *   irreplaceable.
 *
 * Usage (from an ELEVATED PowerShell/terminal - Frida process attach
 * needs SeDebugPrivilege even for same-user processes):
 *   frida -n bzrestore.exe -l bz_unavailable_patch.js
 *
 * The hook must be reattached every time bzrestore.exe restarts. See
 * bz_watch_and_hook.ps1 in this repo for a small watcher that automates
 * that (Windows/PowerShell only).
 */

'use strict';

const DRY_RUN = true; // flip to false only after confirming hit count looks sane

const MODULE_NAME = 'bzrestore.exe';

// --- Addresses specific to v10.0.3.1075 - re-derive for other versions, see README ---
const STATIC_IMAGE_BASE = ptr('0x140000000');
const STATIC_FUNC_ADDR = ptr('0x140012680'); // generic string-assign helper
const STATIC_CALL_SITE_RETURN_ADDR = ptr('0x140187c6b'); // return addr right after the specific CALL in HandleResponseChunk's "unavailable" branch
// ---------------------------------------------------------------------------------

const TARGET_OLD = 'Unavailable';
const TARGET_NEW = 'NeedsDownload';

function main() {
  const mod = Process.getModuleByName(MODULE_NAME);

  // Sanity check: make sure you're hooking the binary that's ACTUALLY running.
  // (Multiple installed copies of the same-named exe, at different versions,
  // is a real trap - see README "Gotchas" section.)
  console.log(`[*] Found ${MODULE_NAME} at: ${mod.path}`);
  console.log(`[*] Double-check this is the copy you expect before proceeding.`);

  const offset = STATIC_FUNC_ADDR.sub(STATIC_IMAGE_BASE);
  const runtimeAddr = mod.base.add(offset);
  const callSiteOffset = STATIC_CALL_SITE_RETURN_ADDR.sub(STATIC_IMAGE_BASE);
  const runtimeCallSiteReturn = mod.base.add(callSiteOffset);

  console.log(`[*] ${MODULE_NAME} base @ ${mod.base}`);
  console.log(`[*] Hooking string-assign helper @ ${runtimeAddr} (static ${STATIC_FUNC_ADDR})`);
  console.log(`[*] Only acting when called from return address ${runtimeCallSiteReturn} (static ${STATIC_CALL_SITE_RETURN_ADDR})`);
  console.log(`[*] DRY_RUN = ${DRY_RUN}`);

  // Persistent replacement string buffer (allocated once, reused forever).
  const newStrBuf = Memory.allocUtf8String(TARGET_NEW);
  const newStrLen = ptr(TARGET_NEW.length);

  let hitCount = 0;
  let ignoredSameContentDifferentSite = 0;
  let ignoredSinceLastStatus = 0;

  // A restore can touch tens of thousands of chunks, and the refresh-loop
  // noise scales with that - a per-call heartbeat gets absurdly spammy on a
  // large batch. Print a quiet one-time proof it's filtering correctly, then
  // just a single status line periodically (time-based, not count-based, so
  // it doesn't scale with batch size).
  const STATUS_INTERVAL_MS = 60000;
  const statusTimer = setInterval(() => {
    if (ignoredSinceLastStatus > 0 || hitCount > 0) {
      const verdict = hitCount > 0
        ? `${hitCount} chunk(s) rescued from Unavailable so far`
        : `all clear - nothing has needed rescuing yet`;
      console.log(`[status] ${new Date().toLocaleTimeString()} - watching (${ignoredSinceLastStatus} routine checks this minute) - ${verdict}`);
      ignoredSinceLastStatus = 0;
    }
  }, STATUS_INTERVAL_MS);

  Interceptor.attach(runtimeAddr, {
    onEnter(args) {
      try {
        // args[0] = RCX = this (destination std::string*)
        // args[1] = RDX = source char* data
        // args[2] = R8  = length (size_t)
        const len = args[2].toInt32();
        if (len !== TARGET_OLD.length) return;

        let text;
        try {
          text = args[1].readUtf8String(len);
        } catch (e) {
          return;
        }
        if (text !== TARGET_OLD) return;

        // Content matches "Unavailable" - now check the caller.
        const isOurCallSite = this.returnAddress.equals(runtimeCallSiteReturn);

        if (!isOurCallSite) {
          ignoredSameContentDifferentSite++;
          ignoredSinceLastStatus++;
          if (ignoredSameContentDifferentSite === 1) {
            console.log(`[filter working] ignoring "Unavailable" assign from an unrelated call site (return=${this.returnAddress}) - this is expected background noise, not touched`);
          }
          return;
        }

        hitCount++;
        console.log(`[HIT #${hitCount}] Genuine HandleResponseChunk "Unavailable" assign intercepted` +
                     (DRY_RUN ? ' (dry-run, not modified)' : ` -> rewriting to "${TARGET_NEW}"`));

        if (!DRY_RUN) {
          args[1] = newStrBuf;
          args[2] = newStrLen;
        }
      } catch (e) {
        console.log(`[!] onEnter exception: ${e.message}\n${e.stack}`);
      }
    }
  });

  console.log('[*] Hook installed. Waiting for genuine chunk-state assignments...');
}

setImmediate(main);
