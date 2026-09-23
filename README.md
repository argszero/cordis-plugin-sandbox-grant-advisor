# @argszero/cordis-plugin-sandbox-grant-advisor

Turns a Windows sandbox **ACL provisioning failure with no path forward** into a
diagnosis the model — and the user reading the transcript — can act on.

```
SetNamedSecurityInfoW failed (Win32 5): grantWrite(D:\ws)
```

Three reports describe this exact line: [discussion #7538], [discussion #7622],
[discussion #7646]. In each one every sandboxed command fails the same way,
before it runs, and the error names neither the missing right nor a remedy.

**This plugin is the stopgap for "the error does not name the outstanding
condition".** It does not repair anything: no ACL is written, no privilege is
requested, nothing is elevated.

## The failure it recognizes

The Windows backend provisions a workspace by writing the directory's DACL and
its mandatory-integrity label in **one** `SetNamedSecurityInfoW` call
(`packages/sandbox/sandbox-windows-acl/src/acl.ts`:

```ts
if (applyResult !== abi.ERROR_SUCCESS) throwWin32(api, 'SetNamedSecurityInfoW', applyResult, `${label}(${path})`)
```

). Two consequences follow from that one line:

1. **The label lives in the SACL, and its half is what gets refused.** The
   owner's implicit rights cover only `READ_CONTROL` and `WRITE_DAC`, so the
   combined apply additionally needs **`WRITE_OWNER` on the directory** — an
   *object right*, which a Full-control directory (the normal workspace case)
   has and a `mkdir`-created one inheriting "Authenticated Users: Modify"
   (`0x1301bf`) does not. This is the backend's own documented prerequisite
   ("granted directories must be caller-owned and grant `WRITE_OWNER`").
2. **It is not `SeSecurityPrivilege`, and elevation is the wrong lever.** That
   is the token-privilege form of the same idea, and it is the hypothesis the
   reports naturally reach for — `whoami /priv` cannot tell the two apart,
   because `WRITE_OWNER` is an object right and never appears in that table.
   Granting Full control to the workspace root needs **no** elevation.

The grant is materialized lazily, on the first confined call, and **nothing is
cached when it throws** — so the same failure repeats per command (850 calls
across 39 sessions in #7622; 52,588 output tokens with no output in #7538),
which is why the loop cannot separate it from ordinary command noise.

## What it does

One listener on the public **`tools/post-execute`** waterfall
(`@deepseek-ai/dsh-tools`). That seam — not `ctx.sandbox.confine` — because it is
the only one that has all three of: the failure text (providers propagate their
error unchanged, and the tool pipeline settles it as an `isError` result), an
agent identity to attribute it to (`exec.agent`), and a channel that speaks to
the model in the same step (`PostToolDecision`'s `additionalContexts`, which the
agent loop turns into a durable user-role message —
`packages/core/agent-loop/src/tool-calls.ts`).

1. **One durable advisory per agent.** On the first recognized failure, the
   result is enriched with a user-role notice that names the missing right, the
   discriminator, and the unelevated fix:

   ```
   Sandbox provisioning failed — no sandboxed command can run in this workspace until its ACL applies.

   What was reported:
     SetNamedSecurityInfoW failed (Win32 5): grantWrite(D:\ws)

   Why it is refused while the directory looks writable: that call is a MERGED write ...
     ... the label half additionally needs WRITE_OWNER on the directory. ...

   Confirm the cause (unelevated) — `icacls` is a normal user command:
     icacls "D:\ws"

   Fix it (unelevated, one line) and then run the command again:
     PowerShell: icacls "D:\ws" /grant "$env:USERNAME:(OI)(CI)F"
     cmd:        icacls "D:\ws" /grant "%USERNAME%:(OI)(CI)F"
   ```

   The notice carries its own producer-owned `source.kind`
   (`sandbox-grant-advisor`) — not the retired `plugin` wrapper, which the
   current session format refuses — and a bounded one-line `summary` for the
   transcript row. The host log gets one matching `warn` line, so the fact
   survives outside the transcript too.
2. **An optional, bounded fail-fast half** (`enforceAfter`, default **0** =
   off). It refuses a call **before dispatch** only when both hold: the
   environment has failed provisioning at least `enforceAfter` times, **and**
   this exact call (tool + canonical arguments) is one this plugin watched fail.
   The budget is `maxDenials` (default 2), after which the call proceeds again.
   The budget is per **episode of brokenness**: a call that finally succeeds stops
   being a denial target and re-arms it, so an environment that breaks twice can
   be refused twice — while a session can always make progress by spending the
   budget it has.

## Install

```sh
npm install @argszero/cordis-plugin-sandbox-grant-advisor
```

Mount it by adding the patch to your profile, or apply the shipped
`cordis.patch.yml`:

```yaml
- insert:
    - id: sandbox-grant-advisor
      name: '@argszero/cordis-plugin-sandbox-grant-advisor'
```

## Configuration

| option | default | meaning |
| --- | --- | --- |
| `enforceAfter` | `0` | Provisioning failures in one agent after which an identical, already-failing call is refused before dispatch. `0` disables the blocking half entirely. |
| `maxDenials` | `2` | Denials one agent may spend per episode of brokenness. Bounded on purpose; re-armed when a watched call finally succeeds. |
| `include` | `[]` | Tool-name wildcard patterns to watch; empty means every tool. |
| `exclude` | `[]` | Tool-name wildcard patterns never watched. |
| `href` | — | URL quoted in the advisory as the upstream thread, instead of the discussion numbers. |

```yaml
- set:
    - id: sandbox-grant-advisor
      config:
        enforceAfter: 3
```

## What it deliberately refuses to explain

Recognition is narrow, because a classifier that names the wrong cause is worse
than one that stays silent.

- **Only the two `...NamedSecurityInfoW` operations are classified.**
  `SetEntriesInAclW` merges access entries in process memory — there is no
  object and no rights involved — so its failure is *not* an ACL-permission
  problem, and neither are the `LocalFree`, `LockFileEx`,
  `SetConsoleCtrlHandler` or `SetEnvironmentVariableW` failures thrown by the
  same package.
- **The Win32 code is kept, not flattened.** `ERROR_ACCESS_DENIED` (5) is the
  case the documented prerequisite explains; another code gets a different
  paragraph that says so instead of borrowing the same sentence.
- **A successful command whose *output* contains the line is not a failure.**
  The gate is the result's error state, not the presence of the text — reading a
  log file that quotes the error must not trigger advice.
- **Only one advisory per agent.** The environment is explained once; repeating
  it per failed command would be noise competing with the failure itself.

## Honest boundaries

- **The Windows path itself cannot be witnessed on macOS**, where this plugin was
  built. What the test suite proves is the decision layer — classification, the
  once-per-agent rule, the fail-fast budget and its self-feeding guard, and the
  wiring to a real cordis `Context` and the real `ToolRuntime` — driven by
  fixtures that throw the producer's exact error shape (`Win32Error`,
  `packages/subprocess/win32-process/src/errors.ts`). It does **not** prove that
  `icacls ... :(OI)(CI)F` fixes a given machine; that is the user's one-line
  experiment, and the advisory says so.
- **It repairs nothing and elevates nothing.** If the directory really is
  Full-control for the caller, the remaining hypothesis is `SeSecurityPrivilege`
  — i.e. the backend's documented prerequisite would be wrong. That is an
  upstream question; the advisory states the discriminator rather than assuming
  the answer.
- **Delivery to the model is the agent loop's.** `additionalContexts` are ferried
  on the settled result here and appended as durable user-role events by
  `agent-loop`; a direct `ctx.tools.execute()` caller with no agent gets no
  advisory (and no agent to explain anything to).
- **It complements `@argszero/cordis-plugin-repeat-guard-escalation`, it does not
  replace it.** That guard keys on **call identity** (identical arguments
  retried); this one keys on the **environment signature**, which is how several
  *different* commands share one cause. Mounting both is sensible.
- **The real fix is upstream.** `grantWrite` already computes
  `hasExactGrant` / `hasExactDeny` / `hasExactLabel` and discards which one was
  false, so the diagnostic that turns a 52-minute detour into one line belongs at
  that site — next to the preflight the grant's lazy materialization wants.

## Compatibility

Harness peers — all three carry the **same** range, quoted in full on purpose
(a partially quoted range admits fewer lines than the published one):

- `@deepseek-ai/dsh-llm@>=0.1.2-rc.1 <0.2.0 || >=0.1.3-alpha.2 <0.2.0 || >=0.1.5-alpha.1 <0.2.0 || >=0.1.6-alpha.1 <0.2.0 || >=0.1.7-alpha.1 <0.2.0` — the only **runtime**
  import: `createUserMessage` and `boundContextSummary`.
- `@deepseek-ai/dsh-agent@>=0.1.2-rc.1 <0.2.0 || >=0.1.3-alpha.2 <0.2.0 || >=0.1.5-alpha.1 <0.2.0 || >=0.1.6-alpha.1 <0.2.0 || >=0.1.7-alpha.1 <0.2.0` and
  `@deepseek-ai/dsh-tools@>=0.1.2-rc.1 <0.2.0 || >=0.1.3-alpha.2 <0.2.0 || >=0.1.5-alpha.1 <0.2.0 || >=0.1.6-alpha.1 <0.2.0 || >=0.1.7-alpha.1 <0.2.0` — imported for their **types** only (`Agent`,
  `ToolExecution`, `PostToolDecision`, …). Nothing is loaded from them at
  runtime, but the shipped `lib/types/index.d.ts` still names them, so a consumer
  on a line outside this range fails to typecheck against this package's own
  declarations; that is a compatibility claim, and it is declared as a peer for
  that reason.
- `@deepseek-ai/cordis@^4.0.2`.

Probed at the newest build of every line the range admits — `0.1.2-rc.1`,
`0.1.3-alpha.2`, `0.1.5-rc.3`, `0.1.6-alpha.2`, `0.1.7-rc.1` (the build the third
report ran) — with `npm run test:probe-lines`, which derives those builds from
this range, installs each one from the registry into a scratch tree and runs the
suite against it. A line whose probe fails is removed from the range rather than
left claimed.

## Development

```sh
npm install
npm test                 # tsc, then the suite (real cordis + real ToolRuntime)
npm run test:probe-lines # install the newest build of each admitted line and run the suite against it
npm run test:probe-lines -- 0.1.7-rc.1  # one line only
```

The suite is mostly control arms: a guard that explains the wrong failure, or
refuses a call that would have worked, is worse than one that stays silent.

[discussion #7538]: https://github.com/deepseek-ai/deepseek-harness/discussions/7538
[discussion #7622]: https://github.com/deepseek-ai/deepseek-harness/discussions/7622
[discussion #7646]: https://github.com/deepseek-ai/deepseek-harness/discussions/7646
