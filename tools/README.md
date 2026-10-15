# `tools/` — the instruments behind the default-DACL measurement

These six scripts are the probes the `native-init` advisory's third producer was
measured with. They are **not** part of the plugin: nothing in `lib/` imports
them, nothing runs them at load time, and no advisory tells a user to run them.
They are here so that a reader who wants to re-run an arm can, instead of taking
a number on trust or scrolling an issue thread.

They were written by **Ethan-H1K**, who offered them in this repository's issue
[#1](https://github.com/argszero/cordis-plugin-sandbox-grant-advisor/issues/1) and
gave credit in the same thread, and they are copied here unedited as the
canonical home that offer asked for. Each file carries a provenance header above
its own header naming the comment it came from; the body underneath that block is
byte-for-byte the text that was posted.

## What you need to run them

- **Windows.** Every script loads `kernel32.dll` / `advapi32.dll` through koffi,
  or drives the Windows restricted-token runner. There is no other-platform arm.
- **An installed desktop build of DeepSeek Harness**, because the runner and its
  dependency closure live inside the packaged `app.asar`.
- **A machine you are willing to change.** These are not read-only instruments:
  the arms run real sandboxed commands, and the ones that rewrite the merged
  default-DACL grant change what a child process is allowed to do. There is a
  `dump-dacl.mjs` and a `dump-groups.mjs`-equivalent path for reading without
  changing anything, and it is the one to start with.

## The knobs

| variable | what it selects | default |
|---|---|---|
| `SBXRUNNER` | file URL of the shipped `…/dsh-sandbox-windows-acl/lib/runner.js`. Both bootstraps exit `2` without it — there is no default, because the path is per-install. | none |
| `SBXVAR` | which arm of the probe hook is installed (see the arm table below). | `baseline` |
| `SBX_ALLOCCONSOLE` | set to `1` to call `AllocConsole()` in the mediator before the child is created — the console axis. | unset |
| `SBX_KOFFI` | override the koffi entry point, which is otherwise derived from `process.execPath`. | derived from the install |
| `KOFFI_URL` | the same override for `dump-dacl.mjs`, which takes it as an argument or from this variable. | derived from the install |
| `SBX_ASAR_NM` | override the `node_modules` directory `materialise-runner.mjs` copies out of. | derived from the install |

## The arms

The arm names are the values `hook.mjs` switches on, plus the two `dacl-patch-hook.mjs`
variants; the outcomes are the rows its author reported on Windows 10 19045, in
issue [#1 comment 6172657585](https://github.com/argszero/cordis-plugin-sandbox-grant-advisor/issues/1#issuecomment-6172657585)
and [comment 6170010818](https://github.com/argszero/cordis-plugin-sandbox-grant-advisor/issues/1#issuecomment-6170010818).
They are quoted as the reporter's rows on one machine, not as this project's
measurement.

| arm | what it varies | exit code reported |
|---|---|---|
| `baseline` | nothing — the shipped call | `0` under `--mode read-only`, `0xC0000142` under `--mode workspace-write` |
| `dacl-everyone` | keeps the shipped grant and **adds** a second one naming `Everyone` | `0` |
| `dacl-synth` | names the synthetic `S-1-4-4242-4242` instead | `0xC0000142` |
| `dacl-wssid` | names the real workspace capability SID instead | `0xC0000142` |
| `dacl-wssid-everyone` | names that capability SID **and** adds `Everyone` | `0` |
| `rl-synth` | adds the synthetic SID to the **restricting list**, DACL untouched | `0` under `--mode read-only`, `0xC0000142` under `--mode workspace-write` |
| `rl-synth-dacl-synth` | that, **and** names the synthetic SID in the DACL | `0xC0000142` |
| `rl-synth-dacl-synth-everyone` | that, **and** adds `Everyone` to the DACL | `0` |
| `both` | `dacl-patch-hook.mjs`'s kept-and-added arm: the shipped call stays and `Everyone` is added beside the capability SID — the same shape as `dacl-everyone`, in the two-file set | `0` |
| `replace` | `dacl-patch-hook.mjs`'s replacement arm: the shipped grant is overwritten by one naming `Everyone`, so the capability SID is not named at all | `0` |

Two readings the table is not allowed to imply, because its author said so:

- **The console masks the other input.** With `SBX_ALLOCCONSOLE=1`, every arm
  above that the console run covered reached `0` — so a row is only about the
  default-DACL input when the mediator owned no console, and the arms that
  separate the two inputs are the ones that vary a trustee while the console
  stays absent.
- **The mode is part of the row, not a detail.** The shipped call falls through to
  `Everyone` under `read-only` and names a capability SID under `workspace-write`
  whenever a temp directory exists, so `baseline` and `rl-synth` — the two rows
  whose DACL is the shipped one — are the two whose outcome differs between the
  modes.

## The files

The "own header" column is a property of each script's **own** comment header,
below the provenance block this repository prepends: whether that header carries
the file's own invocation (the concrete command line to run it) or defers to
another file. The distinction matters because the comment that offered these said
all of them repeated their own invocation, and its author then corrected that:
`dacl-patch-hook.mjs` defers to the bootstrap's `register(...)` call instead. The
same test the author did not run is below — `bootstrap.mjs` and `hook.mjs` are in
the same position, for the same reason.

| file | origin | what it is | own header |
|---|---|---|---|
| `dump-dacl.mjs` | issuecomment-6170010818 | prints the calling process token's `TokenDefaultDacl` as SID + mask; run it as the sandboxed command to dump the **confined child's** default DACL | carries its invocation |
| `dacl-patch-hook.mjs` | issuecomment-6170010818 | the module-loading hook that rewrites the one default-DACL grant in the shipped runner and changes nothing else; `both` adds `Everyone` beside the capability SID, `replace` names `Everyone` instead | defers to `alloc-console-bootstrap.mjs` |
| `alloc-console-bootstrap.mjs` | issuecomment-6170010818 | loads the shipped runner in this process, optionally allocating a console first and/or registering the hook — the entry point for the SID arm and the console arm alike | carries its invocation |
| `materialise-runner.mjs` | issuecomment-6170010818 | copies the runner **and its dependency closure** out of `app.asar` into a real directory, so a plain console-subsystem `node.exe` can host it; without it the console-mediator arm is not reproducible | carries its invocation |
| `hook.mjs` | issuecomment-6172657585 | the two-axis probe hook: one arm per row of the table above, over the restricting list and the default DACL | defers to `bootstrap.mjs` |
| `bootstrap.mjs` | issuecomment-6172657585 | loads the shipped runner with that probe hook registered, and is the shorter of the two bootstraps — it always registers the hook, where `alloc-console-bootstrap.mjs` registers it only when `SBXVAR` is set | defers to this README |

## The package count

`materialise-runner.mjs` copies a dependency closure whose size is a property of
the build, not of this directory, so **this file states no number**. Read it off
the materialiser's own output, which prints it:

```
packages copied (<n>): <name>, <name>, …
```

The one figure that circulated in the thread for this step was written without
tallying the closure, and it was wrong; its author corrected it afterwards, and
the correction is a property of the one build he was running. That is the reason
this text carries neither figure: the size belongs to the build, the tool prints
it, and a number copied into prose outlives the build it was true of. The same
script also prints what it looked for and did not find, and that line is the one
to read before concluding a copy is complete.

The closure is resolved two ways, and both are visible in the script: every
`dependencies` and `peerDependencies` entry of each package copied, then a static
scan of every emitted `.js` for bare `import` / `require` specifiers, repeated
until nothing is missing.

## Honest boundary

- **These arms are one machine's.** Windows 10 19045, the packaged
  console-subsystem mediator, and the build named above. A second build files the
  same shape (`#8721`, Windows 11 26200) and varies no default-DACL input at all,
  so the build axis is open — which is the reason the advisory reads the result as
  `(mode × host × build)` rather than as a rule.
- **Nothing here runs in CI.** The suite checks that these files exist, that the
  tables above name exactly what the scripts implement, and that the bodies parse;
  it cannot check an exit code, because a Windows token is not something a test
  runner has.
- **Do not delete the merged ACE to test any of this.** It is load-bearing for
  every piped grandchild spawn; the arms that matter add a trustee to it rather
  than take one away. The advisory says the same thing for the same reason.
