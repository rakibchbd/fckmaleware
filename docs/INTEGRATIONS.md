# Server security integrations

**Integrations → Server Security** lists Imunify360, ImunifyAV and cPGuard. For each one it shows:

- whether it was detected;
- the installation path;
- the connection test result and when it ran;
- the last sync;
- what FCK Malware can do with it;
- setup steps and troubleshooting.

FCK Malware's own scanner is fully functional without any of them. A product is never shown as connected because it was selected: only a successful test counts.

## What is supported

| Product | Detection | What FCK Malware can do | Interface used |
|---|---|---|---|
| **Imunify360** (CloudLinux) | `/usr/bin/imunify360-agent` or `/usr/sbin/imunify360-agent` is executable | Test (agent version), import the malicious-file list for this site as findings, start an on-demand scan of this site | `imunify360-agent version`, `malware malicious list --json`, `malware on-demand start --path` |
| **ImunifyAV** (CloudLinux) | `/usr/bin/imunify-antivirus` or `/usr/sbin/imunify-antivirus` is executable | Same as Imunify360 | `imunify-antivirus` with the same sub-commands |
| **cPGuard** (OpsShield) | `/opt/cpguard` or `/usr/local/cpguard` is visible to PHP | Status only | None: no documented interface a WordPress site account can call |

### How commands are run

- Only the four fixed binary paths above are accepted. No setting can supply a path, a command or an argument.
- Commands run through `proc_open` with an argument array, so no shell is involved and nothing is interpolated.
- There is a timeout (60 s; 20 s for tests).
- `sudo -n` is used only when "Run through sudo" is on. It never prompts for a password.
- Imported paths are limited to files under this site's root.
- FCK Malware never copies the products' signatures.

### Permissions

The agents normally answer only root. On most shared hosts the web server user may not call them, and the test then reports an error such as "exited with code 1". Ask your host either for:

- an agent configuration that allows the site user; or
- a sudoers rule for exactly that binary, for example:

  ```
  www-data ALL=(root) NOPASSWD: /usr/bin/imunify360-agent
  ```

### When several products run

- Each product detects independently.
- Findings are stored per file and rule. Quarantining a file moves every finding on that file, so the same file is never quarantined twice.
- If a server product cleans or removes a file first, FCK Malware sees the file as gone and resolves the finding instead of failing.
- **When both run** (`primary_scanner`):
  - *FCK Malware handles remediation* (default).
  - *The server scanner handles remediation*: FCK Malware's automatic quarantine pauses while the server scanner is enabled. Manual actions stay available.
- cPGuard results cannot be imported. Keep FCK Malware's automatic quarantine off on cPGuard servers, and review cPGuard's actions in its own panel.

### Limitations

- Not tested against a real Imunify360 or ImunifyAV server. The tests use recorded JSON and an absent agent.
- `open_basedir` can hide `/usr/bin` or `/opt` from PHP. A product then shows as "not detected" even when it is installed; the screen says so.
- With `proc_open` in `disable_functions`, the agents cannot be called at all.
