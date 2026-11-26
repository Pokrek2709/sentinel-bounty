# State-file permissions (v1, round 45, Phase 8)

## The standard

The state directory holds sensitive material: kill-switch state with
token digests, audit records, worker records, backups. The standard
is strict and simple:

- every regular file inside the state directory: **0600**
- every directory inside the state directory: **0700**
- **no symlinks** anywhere inside the state directory

Modes are compared on the permission bits only (mask `0o7777`, so
setuid/setgid/sticky bits are visible: a `2770` directory is a
violation, not just "not 0700"). A mode *more* restrictive than
required (e.g. a `0400` file) is not a violation — it is still
private — and repair never loosens anything.

## What the audit found (2026-11-26)

The writers already enforced 0600/0700 at creation time
(kill-switch, audit log, safe-write, backup), but two gaps let
loose modes survive:

1. **`mkdir({ recursive: true, mode: 0o700 })` never chmods a
   directory that already exists.** The live install's state
   directory was created earlier under umask `0007` and stayed
   `2770` (group-writable + setgid) forever.
2. **Legacy files are never re-tightened.** `budget.json` and
   `default-mode.json` (Nov 18, pre-hardening) sat at `0660`;
   no current code path writes them, so nothing ever fixed them.
3. **Nothing verified permissions at all.** `verify-install` had
   6 checks and none of them looked at modes.

The live check caught exactly those three violations; `verify-install
--fix` repaired all three (dir `2770 -> 0700`, both files
`0660 -> 0600`), and the install now passes 7/7.

## The check

`sentinel verify-install` gained a seventh check,
`state-permissions`, implemented in
`src/policy/state-permissions.js` (`auditStatePermissions`). It
walks the state directory recursively with `lstat` (never follows
a symlink), checks the state directory itself first, then every
entry, and reports each violation by path with its actual mode
and the expected mode. A missing state directory passes ("nothing
to verify yet"). It is read-only, like every other verify-install
check.

## The repair

`sentinel verify-install --fix` repairs *only* state-permission
violations: files to `0600`, directories to `0700`. It reports
each change (`fixed <path>: 0o0660 -> 0o0600`) and each refusal.
Symlinks and other special files are **refused, never followed**
— `chmod` through a symlink would change the target, so repair
leaves them alone and reports `STATE_PERMISSION_SYMLINK_REFUSED`.
Without `--fix`, `verify-install` stays strictly read-only.

## Writer hardening

New writes are private from the start, regardless of umask:

- `ensurePrivateDir(dir)` (in `src/policy/state-permissions.js`)
  creates a directory and then chmods the target directory itself
  to `0700`, closing the existing-directory gap. It is now used by
  the kill-switch writer, the audit-log writer, the drill, and
  backup restore. Only the target directory is chmodded — parents
  are left alone, because they may belong to the operator.
- The backup *output* directory is operator-chosen (it may be
  anywhere), so only a newly created output directory gets `0700`;
  an existing one is never chmodded. The backup *file* itself is
  written `0600`.
- A test proves fresh kill-switch state + audit log are created
  `0600`/`0700` even under umask `022`.

One deliberate exception in `ensurePrivateDir`: a chmod that fails
with `EACCES`/`EPERM` is swallowed, not thrown. It means we do not
own the directory, and the caller's next operation (lock open,
write) will fail with the properly classified permission error
instead. Throwing the raw `EPERM` here regressed the round-27
EACCES probes (they run as `nobody` against a root-owned `0555`
directory). Any other chmod failure still propagates.

## Windows (round 81)

POSIX mode bits do not exist on Windows. Node reports every
regular file as `0666` and every directory as `0777` there, and
`fs.chmod` is a no-op except for the read-only bit — so the
`0600`/`0700` standard is both unstatable and unenforceable on
that platform, and asserting it in tests failed the
`windows-test` workflow on all 53 runs since round 28. The fix:

- `posixModesApply()` in `src/policy/state-permissions.js` is
  the single place that knows this (`platform !== 'win32'`).
- The audit skips mode checks on Windows (`posixModes: false`
  in the result) but still refuses symlinks and special files.
- Repair therefore has no mode violation to tighten on Windows
  and never reports a repair it did not perform (a `chmod` there
  would be a no-op).
- `verify-install` passes the state-permissions check for a
  normal Windows state directory; its PASS message says POSIX
  modes do not apply there instead of claiming `0600`/`0700`.
- Tests assert modes through `tests/helpers/private-mode.js`,
  which enforces exact bits on POSIX and checks existence +
  entry kind on Windows. The mode-behavior tests in
  `tests/state-permissions.test.js` are skipped on Windows;
  `tests/windows-platform.test.js` pins the Windows behavior
  (skipped on POSIX — it is verified by the Windows CI run).
- The privacy guarantee on Windows is the OS ACL, which Node
  cannot observe. That is documented here, not hidden.

Round 82 (2026-11-27) read the first Windows run after this
fix — run 54, head `bcc3037`: conclusion `failure`, the
`npm test` step, exit code 1. The failing test name is not
visible from the lab (the jobs API names only the step, the
check-run has no output, and the log needs admin access), so
no further cause was guessed. Safe status until a Windows run
passes: the fix is implemented but not proven to pass on
Windows.

## Known limitations (honest)

- Permissions are a local-OS control. They do not protect against
  root, against a user who deliberately loosens them afterwards,
  or against an attacker who can rewrite the whole state
  directory. The audit hash chain (round 43,
  `docs/audit-integrity-v1.md`) is the tamper-evidence layer for
  that threat.
- Repair only tightens; it never deletes a symlink or a special
  file. Removing one is an operator decision.
- The check covers the state directory tree only. Backup files
  the operator copies elsewhere keep whatever mode the copy
  operation gives them — the backup file itself is written `0600`,
  but a later `cp` without `-p` will not preserve it.
