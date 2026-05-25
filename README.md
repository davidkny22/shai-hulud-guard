# shai-hulud-guard

Protection against the Shai-Hulud npm supply chain attacks. One install, runs in the background, no dependencies.

---

Since September 2025, the Shai-Hulud worm has compromised 170+ npm packages across 400+ malicious versions. It steals npm tokens, GitHub PATs, and cloud credentials from developer machines, then uses those tokens to publish infected versions of other packages the victim maintains. The attack spreads through `postinstall` and `prepare` lifecycle scripts -- meaning `npm install` alone is enough to get hit.

Affected packages include @tanstack/react-router, @mistralai/mistralai, @uipath/cli, @crowdstrike/foundry-js, @opensearch-project/opensearch, @cap-js/sqlite, and many others across five campaign waves through May 2026.

This tool does three things:

1. **Blocks lifecycle scripts by default.** Your `npm install`, `pnpm install`, and `yarn install` commands are aliased to always run with `--ignore-scripts`. This prevents the worm's entry point from executing, even if a compromised version ends up in your dependency tree.

2. **Scans for known compromised packages.** After every install, your lockfile and `node_modules` are checked against a blocklist of every known malicious package@version and against the specific IOC files the worm drops (`router_init.js`, `tanstack_runner.js`, `setup_bun.js`).

3. **Monitors in the background.** A lightweight daemon checks your dev directories every 5 minutes for new IOC files, exfiltration connections to `webhook.site`, and processes polling `api.github.com/user`.

## Install

### macOS / Linux

```bash
git clone https://github.com/davidkny22/shai-hulud-guard
cd shai-hulud-guard
bash install.sh
```

### Windows

```powershell
git clone https://github.com/davidkny22/shai-hulud-guard
cd shai-hulud-guard
powershell -ExecutionPolicy Bypass -File install.ps1
```

Restart your shell. That's it.

The installer sets up the blocklist, scanner, background monitor (macOS LaunchAgent, Linux cron, or Windows Task Scheduler), and shell aliases / PowerShell profile functions. No account, no cloud, no dependencies beyond bash or PowerShell.

## What happens after install

```bash
$ npm install express
[shai-hulud-guard] Running npm install express --ignore-scripts
[shai-hulud-guard] Scanning for compromised packages...
[OK] No Shai-Hulud indicators found
```

Every install command is intercepted, lifecycle scripts are suppressed, and a scan runs automatically. If you need to run scripts for a trusted project:

```bash
command npm install    # bypasses the alias
```

## What it catches

**IOC files** (matched by SHA-256 hash or filename):
- `router_init.js` -- primary Mini Shai-Hulud payload
- `tanstack_runner.js` -- worm runner
- `setup_bun.js`, `bun_environment.js` -- Shai-Hulud 2.0 droppers

**Delivery mechanism:**
- `github:tanstack/router#<branch>` entries in `optionalDependencies`
- Dune-themed git branch references used as dead-drop commit pointers (`atreides`, `fremen`, `sardaukar`, `melange`, etc.)

**Exfiltration:**
- Active connections to `webhook.site`
- Processes polling `api.github.com/user`
- `rm -rf` processes (destructive Shai-Hulud 2.0 fallback)

**Compromised packages** -- full blocklist covering all five campaign waves:

| Campaign | Date | Scale |
|----------|------|-------|
| Shai-Hulud | Sep 2025 | @ctrl/\*, @crowdstrike/\*, @nativescript-community/\* |
| Shai-Hulud wave 2 | Nov 2025 | @operato/\*, @things-factory/\* |
| Shai-Hulud 2.0 | Dec 2025 | Destructive variant, 25K+ GitHub repos |
| Mini Shai-Hulud (SAP) | Apr 2026 | @cap-js/\*, mbt |
| Mini Shai-Hulud (TanStack) | May 2026 | @tanstack/\*, @mistralai/\*, @uipath/\*, @squawk/\*, 170+ packages |

The complete version-level blocklist is in [`blocklist/shai-hulud-blocked-packages.txt`](blocklist/shai-hulud-blocked-packages.txt).

## How the attack works

1. Attacker steals an npm maintainer's publish token (often from a prior infection)
2. Publishes a patched version of a real package with a new `optionalDependency` pointing to a GitHub repo
3. The repo has a `prepare` script that runs a payload via Bun
4. The payload harvests `.npmrc`, GitHub PATs, AWS/GCP/Azure keys, K8s service accounts, OIDC tokens
5. Stolen npm tokens are used to find and infect more packages the victim can publish

The `--ignore-scripts` alias breaks this at step 3. The scanner catches it at step 2. The monitor catches the aftermath if anything slips through.

## Manual scanning

```bash
# macOS / Linux
shai-hulud-scan /path/to/project
tail -20 ~/.shai-hulud-guard/log/monitor.log
```

```powershell
# Windows
shai-hulud-scan C:\path\to\project
Get-Content ~\.shai-hulud-guard\log\monitor.log -Tail 20
```

## Updating the blocklist

```bash
cd shai-hulud-guard
git pull
cp blocklist/shai-hulud-blocked-packages.txt ~/.shai-hulud-guard/blocklist/
```

## Limitations

- Covers **known** compromised versions. New infections require a blocklist update.
- `--ignore-scripts` is the real protection layer. If you bypass the alias and manually execute scripts from a compromised package, the malware can still run.
- The background monitor watches `~/Documents/GitHub`, `~/Projects`, `~/dev`, `~/code`, `~/src`, and `~/workspace`. Edit `WATCH_DIRS` in `bin/shai-hulud-monitor.sh` for your setup.
- Windows support requires PowerShell 5.1+ and uses Task Scheduler instead of cron/LaunchAgent.

## Uninstall

```bash
# macOS
launchctl unload ~/Library/LaunchAgents/com.shai-hulud-guard.monitor.plist
rm ~/Library/LaunchAgents/com.shai-hulud-guard.monitor.plist

# Linux
crontab -l | grep -v "shai-hulud-monitor" | crontab -

# macOS / Linux shared
rm -rf ~/.shai-hulud-guard
# Remove the "Shai-Hulud Guard" block from your .zshrc or .bashrc
```

```powershell
# Windows
Unregister-ScheduledTask -TaskName 'ShaiHuludGuardMonitor' -Confirm:$false
Remove-Item -Recurse -Force "$env:USERPROFILE\.shai-hulud-guard"
# Remove the "Shai-Hulud Guard" block from your PowerShell profile
```

## Contributing

PRs welcome. The most useful contributions right now:

- New compromised package versions for the blocklist
- Additional IOC file signatures
- Bun and Deno support
- CI/CD integration (GitHub Actions, GitLab CI)

## Sources

Threat intelligence compiled from [Aikido](https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised), [Socket.dev](https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack), [Wiz](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised), [Unit 42](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/), [Microsoft](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/), [Snyk](https://snyk.io/blog/tanstack-npm-packages-compromised/), [StepSecurity](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem), and [Netskope](https://www.netskope.com/blog/shai-hulud-2-0-aggressive-automated-one-of-fastest-spreading-npm-supply-chain-attacks-ever-observed).

## Disclaimer

This tool provides defense-in-depth against known Shai-Hulud campaign variants and IOCs. It is not a guarantee of protection. New attack vectors, unknown compromised packages, and novel supply chain techniques may not be detected. Use alongside other security practices (token rotation, 2FA, dependency auditing). The authors are not liable for any damages resulting from supply chain attacks. See [LICENSE](LICENSE).

## License

[MIT](LICENSE)
