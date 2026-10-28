# PHP2Shell Tenable Skill

A Claude Code skill that turns your own Tenable data into a verified action plan for PHP2Shell (CVE-2026-109618 and CVE-2026-109619, pre-authentication remote code execution in PHP). It pulls findings through the [Tenable Hexa AI MCP](https://docs.tenable.com/vulnerability-management/Content/getting-started/hexa-AI-MCP.htm), checks each PHP install against the fixed releases and public vendor advisories, and writes a ranked fix list with an owner and a next step for every host. Hosts it can't verify are listed separately, with the reason.

The plugin IDs, fixed versions and mitigations come from Tenable Research's [PHP2Shell FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote).

## What it does

1. Checks that the Tenable Hexa AI MCP tools are loaded. If they are missing, it prints the setup command and stops.
2. Re-reads the Tenable Research FAQ for the current CVE list, fixed releases and mitigations, then asks Tenable's plugin database for every plugin covering those CVEs (`faq.json`, `plugins.json`). That picks up Nessus and cloud or container plugins as Tenable publishes them.
3. Finds vulnerable findings by CVE, and reads PHP inventory and plugin output from the detection plugins (48243, 58987, 200476 and 216936). `source` comes from repeating the CVE query per product, and the CVE list is the PHP2Shell CVEs only.
4. Adds context for each asset: whether it was scanned with working credentials, whether it serves HTTP, whether Scan for Unpatched Vulnerabilities was on (read from plugin 19506 for the host's scan run), its AES and ACR, whether it is on an attack path, its operating system and its owner (`findings.json`, `assets.json`).
5. Downloads public vendor advisories with `fetch_advisories.py`.
6. Runs `render.py`, which verifies each install, ranks the hosts and writes the plan and reports.
7. Summarizes the run in the chat: the credential picture first, counts per bucket, the top items with owner and action, and what needs verifying.

The skill only reads data in Tenable. It never launches scans, creates tags or changes anything.

## Prerequisites

- **Claude Code.**
- **Tenable One Foundation or Advanced.** Hexa AI MCP must be turned on under Settings > Hexa AI, and your role must be Standard User or higher. The Hexa MCP is not available in FedRAMP Moderate environments.
- **Tenable API keys**, generated under Settings > My Account > API Keys.
- **Credentialed scans.** A host's installed package version, and so its status, can only be verified when Tenable scanned it with working credentials (or with a Nessus Agent). Hosts without them are listed under Verify first.
- **Python 3.** The scripts use only the standard library.
- **Google Chrome or Chromium** for the PDF. Without either, the other files are still written and the PDF is skipped with a warning.

## Install

1. Add the Tenable Hexa AI MCP server to Claude Code, using your own keys:

   ```bash
   claude mcp add --transport http tenable https://cloud.tenable.com/mcp \
     --header "X-ApiKeys: accessKey=<ACCESS_KEY>;secretKey=<SECRET_KEY>"
   ```

2. Clone this repository into your Claude Code skills directory:

   ```bash
   git clone https://github.com/securibee/php2shell-tenable-skill ~/.claude/skills/php2shell-tenable
   ```

3. Restart Claude Code so it loads both the MCP server and the skill.

## Usage

Run `/php2shell-tenable`, or ask Claude something like "run the PHP2Shell report" or "which of our assets are exposed to PHP2Shell?".

A run takes a few minutes. Most of that is Hexa calls, which the skill paces, backing off and retrying on HTTP 429.

### Owner file

To put an owner against every host, give the skill a CSV from your CMDB or a spreadsheet. The first run asks for it and remembers the path in `~/Dev/php2shell-reports/config.json` (keys `owner_file` and `owner_tag_category`).

```csv
hostname,owner
web01.example.com,Platform Team
web02.example.com,Payments
```

- A column named `owner` is required, plus at least one of `asset_id`, `hostname`, `fqdn` or `ip`.
- Headers are not case-sensitive, matching ignores case, and a UTF-8 BOM (as Excel writes) is fine.
- Rows with a blank owner are ignored. When a host matches several rows, the first non-blank owner wins.
- The owner file wins over Tenable tags. Without one, the skill looks for an ownership-like tag category (Owner, Team, Business Unit), asks you to confirm it once, and remembers it. Hosts with neither show as unassigned.

## Output

Each run writes to `~/Dev/php2shell-reports/<YYYY-MM-DD-HHMM>/`:

| File | Contents |
|---|---|
| `action-plan.json` | The plan for people and agents: ranked items, hosts to verify first, the evidence behind each verdict, the data sources used. Validated by `schemas/action-plan.schema.json`. |
| `report.html` | A self-contained page with the buckets by owner, the ranked table, per-host detail, Verify first, and the credential follow-up. It has a PDF button and needs no network access to view. |
| `report.pdf` | A US Letter landscape version. Page 1 is the summary. |
| `report.csv` | One row per PHP install with every plan field. |
| `auth-followup.txt` | Hosts whose credentials failed (asset ID, hostname, IP, failing plugin), for the Auth Failure Analyzer. |
| `advisories/` | The vendor advisory responses `fetch_advisories.py` downloaded, with `index.json` recording each fetch and whether it succeeded. |
| `findings.json`, `assets.json`, `plugins.json`, `faq.json` | The Tenable data the plan was built from. |

### Buckets

| Bucket | Meaning |
|---|---|
| Fix FIRST | Confirmed vulnerable and internet-facing: a Web App Scanning finding or a public IP address. |
| Fix NEXT | Confirmed vulnerable and serving web requests. |
| Fix SOON | Confirmed vulnerable, and every PHP install is command-line only: no php-fpm, php-cgi or Apache PHP module, a complete install list, no HTTP service recorded (plugin 10107) and no Web App Scanning finding. |
| Verify first | Not yet confirmed either way. Each host has a next step. |

Within a bucket, hosts are ranked by attack path level (critical, then high), then by Tenable's ACR and AES. Each Fix item carries an action: `patch`, `vendor-update`, `upgrade-stream` or `isolate-or-upgrade`.

### Statuses

Each PHP install gets one of these verdicts:

| Status | Meaning |
|---|---|
| Vulnerable | Below the fixed release, or a vendor fix exists and is not installed. |
| Vulnerable – no vendor fix | The vendor has published no fix yet. Mitigate and watch for one. |
| Vulnerable – no fix for this stream | The vendor ships no fix for the installed PHP stream. Upgrade to a supported one. |
| Vulnerable – backport only | PHP 7.4–8.1. No official release; fixes come only as source or vendor backports. |
| Vulnerable – EOL | PHP 5.4–7.3. End of life, and the PHP project will not ship a fix. |
| Patched | Positive evidence of the fix: a version at or above the fixed release, or a vendor package at or above the vendor fix. |
| Likely patched – Tenable distro check clean | Tenable's distro plugins don't fire, and the plugin for this release was published before the host's last scan. No vendor feed confirms the fix: the skill reads none for Oracle Linux, Amazon Linux, CentOS or Fedora, and without a package version there is nothing to compare. Listed under Verify first, never shown as Patched. |
| Not affected | Below PHP 5.4. |
| Conflict – verify | Two positive sources disagree. |
| Unverified – credentials | The host wasn't scanned with working credentials. |
| Unverified – no package data | The data the skill read can't settle the install: no package or version, no vendor feed record for the package, or a feed that failed to download. The next step says which. |

A feed that fails to download is never read as a fix.

### Credential follow-up

When hosts were scanned without working credentials, the report and the chat summary open with one sentence saying how many. For hosts where credentials were tried and failed, `auth-followup.txt` lists them by failing plugin. The [Auth Failure Analyzer](https://exchange.tenable.com/skills/auth-failure-analyzer/) skill, listed on the CyberAgents Exchange (install steps on the listing; the source is `nsolimini/auth-failure-skill` on GitHub), can find the cause. This skill only recommends it and never runs it. Hosts with no credentials configured need credentialed scans set up instead.

## Re-render

You can re-render from a saved run folder without calling Tenable again:

```bash
python3 ~/.claude/skills/php2shell-tenable/fetch_advisories.py <run folder>
python3 ~/.claude/skills/php2shell-tenable/render.py <run folder> [--owners <owner file>]
```

Without `--owners`, `render.py` uses the owner file remembered in `config.json` beside the run folder. If that file has moved, it stops and names it; pass `--owners` with the new path.

## Data flows

- **Tenable Hexa AI MCP** (`https://cloud.tenable.com/mcp`). The skill sends read-only queries with your API keys.
- **Your LLM provider.** As with any MCP server, the asset data Hexa returns passes through Claude Code to the model you use. The skill records which authentication plugins fired on a host, never their output.
- **tenable.com.** The skill fetches the Tenable Research FAQ once per run for the current CVEs, fixed releases and mitigations.
- **OSV.dev, Red Hat and Alpine.** `fetch_advisories.py` makes unauthenticated GET requests to OSV.dev, Red Hat's CSAF VEX files and the Alpine secdb. Only CVE IDs, advisory IDs and release numbers go in the requests; no host data is sent.
- **No network access from `render.py`.** It writes local files and runs a local headless Chrome against them. The font, logo and images are embedded in the HTML. The report's links (the FAQ, the Auth Failure Analyzer listing and advisory URLs) only open if you click them.

## Known limitations

- **Credentials.** Hosts scanned without working credentials can't be verified; rescan with credentials.
- **Output length.** The skill reads up to about 500 characters of each plugin output, so for a host with three or more PHP installs it may see only the first ones; the report flags these hosts.
- **Oracle Linux, Amazon Linux, CentOS and Fedora.** The skill reads no vendor feed for these; their hosts rely on Tenable's plugins and can reach Likely patched, not Patched.
- **Vendor data.** Vendor data can be wrong; vendor "not affected" claims are recorded, not trusted alone.
- **Unpatched-vulnerability scanning.** Turn on Scan for Unpatched Vulnerabilities in the scan policy so Tenable can report packages with no vendor fix. The report shows the setting per host.
- **Web App Scanning results come from scans on or after 21 October 2026,** the day the WAS plugins were published.
- **Fixed findings are excluded.** Findings Tenable marks `FIXED` are left out of the report.

## Repository layout

```
SKILL.md                   skill instructions Claude Code loads
fetch_advisories.py        downloads vendor advisories into <run folder>/advisories/ (the only network use)
render.py                  run folder -> action-plan.json, report.html, report.pdf, report.csv, auth-followup.txt
verify.py, plan.py         per-install verdicts, then ranking, owners and the plan
inventory.py, versions.py  plugin output parsing and package version comparison
advisories.py              reads the downloaded advisory files
schemas/                   JSON Schema for action-plan.json
tests/                     unit tests (standard library only)
assets/report.html         report template (design tokens from the CyberAgents Exchange website)
assets/*                   Work Sans font with its license (OFL.txt), Tenable logo and iris
```

## Tests

From the repository root:

```bash
python3 -m unittest discover -s tests -t . -v
```

## License

MIT, copyright Tenable, Inc. See [LICENSE](LICENSE).

The bundled Work Sans font is licensed separately under the SIL Open Font License 1.1 ([assets/OFL.txt](assets/OFL.txt)). The Tenable name, logo and iris mark are trademarks of Tenable, Inc. They are included only to brand the generated reports and are not licensed under MIT.
