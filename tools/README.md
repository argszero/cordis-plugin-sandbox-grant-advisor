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
  `dump-dacl.mjs` is the read-only path for reading without changing anything, and it
  is the one to start with.

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
variants. The hook shipped here is the **twenty-arm** file its author posted in
[comment 6196102774](https://github.com/argszero/cordis-plugin-sandbox-grant-advisor/issues/1#issuecomment-6196102774):
the eight cases of the version posted earlier keep their bodies, and the twelve arms
his later rows report are appended ahead of its `default` case, which is why the
table's first ten rows could be read out of the file from the beginning and the other
twelve could not. A table row no case answers is a row a reader cannot run.

The outcomes are the rows its author reported on Windows 10 19045 — the first ten in
[comment 6172657585](https://github.com/argszero/cordis-plugin-sandbox-grant-advisor/issues/1#issuecomment-6172657585)
and [comment 6170010818](https://github.com/argszero/cordis-plugin-sandbox-grant-advisor/issues/1#issuecomment-6170010818),
the other twelve in
[comment 6191353481](https://github.com/argszero/cordis-plugin-sandbox-grant-advisor/issues/1#issuecomment-6191353481).
They are quoted as the reporter's rows on one machine, not as this project's
measurement. Two of the twelve, `nosids` and `noli`, come from the A/B table of
1 October in [discussion #8497](https://github.com/deepseek-ai/deepseek-harness/discussions/8497)
rather than from a posted hook; they are here because they are the two arms that
bound the statement from the other side, and their author reports both as not
recovering.

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
| `nosids` | takes the write SIDs back OUT of the restricting list the call site builds, the shipped DACL untouched | `0xC0000142` |
| `noli` | drops the integrity-level lowering, everything else shipped | `0xC0000142` |
| `dacl-interactive` | names `S-1-5-4` (INTERACTIVE) in the merged ACE, the restricting list left as shipped | `0xC0000142` |
| `dacl-authusers` | names `S-1-5-11` (Authenticated Users) there, list left as shipped | `0xC0000142` |
| `dacl-admins` | names `S-1-5-32-544` (Administrators) there, list left as shipped | `0xC0000142` |
| `everyone-no-logon` | names `Everyone` in the merged ACE **and** removes the logon SID from the restricting list | `0xC0000142` |
| `everyone-no-world` | names `Everyone` there **and** removes `Everyone` from the restricting list | `0xC0000142` |
| `rl-named-interactive` | names `S-1-5-4` in the merged ACE **and** appends that SID to the restricting list | `0` |
| `rl-named-authusers` | names `S-1-5-11` there **and** appends it to the list | `0` |
| `rl-named-synth` | names the synthetic `S-1-4-4242-4242` there **and** appends it to the list | `0xC0000142` |
| `rl-named-interactive-no-world` | `rl-named-interactive`'s two edits, **and** removes `Everyone` from the list | `0xC0000142` |
| `rl-named-admins` | names `S-1-5-32-544` in the merged ACE **and** appends it to the list | `0xC0000142` |
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
- **The last four `rl-named-*` rows are the ones that made the statement three
  parts.** `dacl-interactive` and `dacl-authusers` name an enabled group of the
  token and die; `rl-named-interactive` and `rl-named-authusers` name the same two
  SIDs and append them to the restricting list, and recover. The pair is the
  measurement: a named trustee that is an enabled group is necessary and not
  sufficient, and the third part is what `everyone-no-logon`,
  `everyone-no-world` and `rl-named-interactive-no-world` remove one at a time.
  `rl-named-admins` is the counterexample to the first part alone — a group of the
  token, deny-only at `0x10`, which dies even with the list carrying it.

## The files

The "own header" column is a property of each script's **own** comment header,
below the provenance block this repository prepends: whether that header carries
the file's own invocation (the concrete command line to run it) or defers to
another file. The distinction matters because the comment that offered these said
all of them repeated their own invocation, and its author then corrected that:
`dacl-patch-hook.mjs` defers to the bootstrap's `register(...)` call instead. The
same test the author did not run is below — `bootstrap.mjs` and `hook.mjs` are in
the same position, for the same reason.

**One instrument the reporter names is not here.** `dump-groups.mjs` — the
`TokenGroups` twin of `dump-dacl.mjs`, printing each group with its attributes —
was described twice and its body was never posted, so this directory carries
neither it nor a reconstruction of it: a script rebuilt from a description would be
this repository's text under his name, and the next reader would have no way to
tell the two apart. The `TokenGroups` rows the advisory quotes are therefore the
reporter's, read off his own output. What is re-runnable from here is the
default-DACL dump and the arms.

| file | origin | what it is | own header |
|---|---|---|---|
| `dump-dacl.mjs` | issuecomment-6170010818 | prints the calling process token's `TokenDefaultDacl` as SID + mask; run it as the sandboxed command to dump the **confined child's** default DACL | carries its invocation |
| `dacl-patch-hook.mjs` | issuecomment-6170010818 | the module-loading hook that rewrites the one default-DACL grant in the shipped runner and changes nothing else; `both` adds `Everyone` beside the capability SID, `replace` names `Everyone` instead | defers to `alloc-console-bootstrap.mjs` |
| `alloc-console-bootstrap.mjs` | issuecomment-6170010818 | loads the shipped runner in this process, optionally allocating a console first and/or registering the hook — the entry point for the SID arm and the console arm alike | carries its invocation |
| `materialise-runner.mjs` | issuecomment-6170010818 | copies the runner **and its dependency closure** out of `app.asar` into a real directory, so a plain console-subsystem `node.exe` can host it; without it the console-mediator arm is not reproducible | carries its invocation |
| `hook.mjs` | issuecomment-6196102774 | the two-axis probe hook: one arm per row of the table above, over the restricting list and the default DACL — twenty cases, the twelve later arms appended ahead of its `default` | defers to `bootstrap.mjs` |
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
