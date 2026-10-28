---
name: php2shell-tenable
description: PHP2Shell (CVE-2026-109618, CVE-2026-109619) verified action plan from Tenable data via the Tenable Hexa AI MCP, written as JSON, HTML, PDF and CSV. Use when someone asks which assets are exposed to PHP2Shell, wants a PHP2Shell report, or asks about the PHP RCE plugins in Tenable VM or Web App Scanning.
---

# PHP2Shell Tenable Skill

Builds one verified action plan for PHP2Shell: which hosts to fix first, which fix to apply, who owns the host, and which hosts cannot be verified yet. The data comes from the **Tenable Hexa AI MCP** and nothing else: every asset, version and finding in the report traces back to a Hexa tool call made during this run.

Source of truth for CVEs, fixed versions and mitigations: [Tenable Research PHP2Shell FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote).

## Plugins

| Plugin | Product | Name | Role |
|---|---|---|---|
| 115719 | WAS | PHP 8.5.x < 8.5.12 Multiple Vulnerabilities | vulnerable |
| 115720 | WAS | PHP 8.4.x < 8.4.27 Multiple Vulnerabilities | vulnerable |
| 115721 | WAS | PHP 8.3.x < 8.3.36 Multiple Vulnerabilities | vulnerable |
| 115722 | WAS | PHP < 8.2.35 Multiple Vulnerabilities | vulnerable |
| 369483 | VM (Nessus) | PHP < 8.2.35 / 8.3.x < 8.3.36 / 8.4.x < 8.4.27 / 8.5.x < 8.5.12 Multiple Vulnerabilities (CGI abuses, version-based) | vulnerable |
| 48243 | VM (Nessus) | PHP Version Detection | inventory |
| 58987 | VM (Nessus) | PHP Unsupported Version Detection | inventory |
| 200476 | VM (Nessus) | PHP Scripting Language Installed (Windows) | inventory |
| 216936 | VM (Nessus) | PHP Scripting Language Installed (Unix) | inventory |

The vulnerable rows are a starting point: step 2 finds every plugin Tenable has for the CVEs, including Nessus and cloud or container plugins this table lacks. Inventory rows carry the PHP installs; `render.py` checks them against the fixed releases (8.5.12, 8.4.27, 8.3.36, 8.2.35) and the vendor feeds that `fetch_advisories.py` downloads.

The skill never changes anything in Tenable. It calls read tools only, and it never launches scans, creates or applies tags, or edits settings. The tools it uses, all read tools: `plugins_search_plugins`, `tenable_one_search_findings`, `tenable_one_list_inventory_properties`, `tenable_one_search_assets`, `tenable_one_search_tags`, `tagging_list_tag_categories_and_values`, `workbenches_get_vulnerability_outputs` and `workbenches_get_asset_info`.

## Steps

All data files go in one run folder, `~/Dev/php2shell-reports/<YYYY-MM-DD-HHMM>/`. Create it in step 2 and write every file below into it.

1. **Preflight.** Look for the Hexa tools in your tool list, e.g. `mcp__tenable__workbenches_list_vulnerabilities` (the prefix follows whatever name the server was added under). If they are absent, stop and give the user this setup, then end the run:
   ```
   claude mcp add --transport http tenable https://cloud.tenable.com/mcp \
     --header "X-ApiKeys: accessKey=<ACCESS_KEY>;secretKey=<SECRET_KEY>"
   ```
   Requirements: Tenable One Foundation or Advanced, **Enable Hexa AI MCP** turned on in Hexa AI settings, API keys from Settings > My Account > API Keys, and Standard User or higher. Restart Claude Code after adding the server.
   *Done when the Hexa tools are callable, or the user has the setup block.*

2. **Coverage.** Both sources, merged. Read each tool's schema before calling it.
   - **FAQ:** WebFetch the FAQ URL above. Take the CVE list: CVE-2026-109618 and CVE-2026-109619, plus any CVE the FAQ explicitly calls part of PHP2Shell. The FAQ also lists related or older CVEs (a bundled-library bug, a session-upload-progress advisory, older KEV entries); do not add those, or the plan fills with findings that are not PHP2Shell. Also take the fixed release per PHP branch, the interim mitigations, the exploitation date and any inventory plugin IDs the table lacks. Write `faq.json`: `{"url", "read_at", "cves", "fixed": {"8.5": "8.5.12", ...}, "mitigations": [...], "exploitation_since"}`. If the fetch fails, skip `faq.json`; the scripts then use the defaults (8.5.12, 8.4.27, 8.3.36, 8.2.35, exploitation since 2026-10-17) and the report says the FAQ was not read. If the fixed releases differ from those defaults, say so in the summary.
   - **Plugins:** call `plugins_search_plugins(cve=<CVE>)` for each CVE with `sort=newest` and page until the last page. With `sort=newest`, paging returns each plugin exactly once, so always pass it. Results are text: each hit is `Plugin <id>: <name>` followed by labelled lines (`Family`, `Sensor`, `Scan Type`, `Published`). Each hit's `Sensor:` line is that row's sensor; ignore `Supported Sensors:`. One plugin can come back as two hits, one per sensor: keep both, and dedupe by plugin ID plus sensor. Write `plugins.json`, a list of `{"plugin_id", "name", "family", "scan_type", "sensor", "published"}`, converting `Published` from `MM/DD/YYYY` to `YYYY-MM-DD`.
   *Done when every CVE has been paged to the end, `plugins.json` is written, and it holds every vulnerable table ID that the CVE search returned. The inventory plugins carry no CVE, so they are not expected in `plugins.json`.*

3. **Pull data.** These routes work; back off and retry on HTTP 429.
   - **Vulnerable findings:** call `tenable_one_search_findings` with `filters` set to `[{"property":"finding_cves","operator":"=","value":[<every CVE from step 2>]}]`. A list of values matches any of them. Page with `offset` while `total` exceeds what you have. The skill's query returns the finding ID, name, asset ID, state and severity, so `product`, CVE list, port, last-seen and plugin ID are not in the result. Get `source` by repeating the same CVE query with one more filter on `product` (call `tenable_one_list_inventory_properties` for the findings entity to list the filterable property names): `{"property":"product","operator":"=","value":["TENABLE:CLOUD"]}` gives `Cloud`, `TENABLE:WAS` gives `WAS`, and the findings in neither set are `VM`. Never infer it from the name. Cloud findings are named by CVE and have no plugin ID, so leave `plugin_id` blank for them. For VM and WAS findings, match the finding's name to the `plugins.json` name for the plugin ID. `last_seen` for a VM host comes from `workbenches_get_asset_info`; `port` and the `last_seen` of Cloud findings may be blank, and that is fine.
   - **Inventory findings:** for each inventory plugin ID (48243, 58987, 200476, 216936, plus any new ones from the FAQ), call with `[{"property":"finding_detection_id","operator":"contains","value":["<plugin id>"]}]`: one ID per call, with `{"property":"finding_severity","operator":"=","value":["INFO"]}` added (these plugins are all INFO, and `contains` also matches CVE names such as CVE-2025-22869). This property takes `contains` with a single value per call. `contains` also matches longer IDs (`58987` hits plugin 158987), so keep only findings whose name contains "PHP".
   - **State:** keep findings that are `ACTIVE` or `RESURFACED` and skip `FIXED`.
   - **Plugin output for inventory plugins:** call `workbenches_get_vulnerability_outputs(plugin_id)`. It returns up to 10 distinct plugin outputs per call, each with every host that shares it, then "... and N more outputs". Only when a call ends with the "... and N more outputs" marker, repeat it with `age` set to 1, 7, 14, 30, 90, 180 and 365 and merge by asset ID; without the marker the first call is complete. A smaller `age` covers fewer hosts, and every call still returns only its first 10 outputs, so the narrow windows are the ones that surface outputs the full call cut off; the wide windows mostly repeat the same 10. A host that no window reaches is written as in "Assets that still have no output" below. Each search hit's output is a block that starts at `Output N:`. Keep the raw text as returned: everything between that output's `Plugin Output:` header and the next `Output N:` header, including indentation and any `... (truncated)` marker. The skill reads up to about 500 characters of each output; when an output ends with the marker, the scripts flag the host as possibly having more installs than it lists.
   - **Assets that still have no output:** call `workbenches_get_asset_info(asset_id)` for the hostname and IP, and write the row with a blank `plugin_output`. `workbenches_get_asset_info` covers VM assets; for cloud and container assets, take the name from `tenable_one_search_assets` instead and leave IP and OS blank.
   *Done when every plugin ID has a recorded result count and every active asset is a row. Zero counts as a result; an ID you never queried does not.*

4. **Write `findings.json` and `assets.json`.**
   - `findings.json` is a JSON list with one row per asset x plugin, and for Cloud, which has no plugin ID, one row per finding (each CVE-named finding is its own row): `asset_id`, `asset`, `ip`, `fqdn`, `url` (WAS only), `source` (`VM`, `WAS` or `Cloud`), `plugin_id` (a string, blank for Cloud), `plugin_name`, `cves` (list), `role` (`vulnerable` for a CVE finding, `inventory` for a PHP detection plugin), `php_version`, `port`, `last_seen` (`YYYY-MM-DD`). Add `plugin_output` only for inventory plugins 216936, 48243, 58987 and 200476; omit it for every other plugin.
   - `assets.json` is an object keyed by the asset ID, else `asset|ip`, else the URL. For each asset with a finding, set:
     - `name`, `ips` (list), `fqdns` (list), `last_seen`.
     - `os`: the operating system string from `workbenches_get_asset_info`; blank if none.
     - `sensors`: the sources of the asset's findings (`"VM"`, `"WAS"`, `"Cloud"`), plus `"agent"` when asset info shows a Nessus Agent. Take sensors from the findings and asset info, not from `tenable_one_search_assets`.
     - `aes` and `acr`: call `tenable_one_search_assets` in batches with the filter `asset_id` `=` a list of IDs. Write JSON numbers, never strings; `N/A` or missing becomes `null`.
     - `apa_level`: `"critical"` for assets matched by `apa_asset_critical_paths_count > 0`, else `"high"` for `apa_asset_high_paths_count > 0`, else `null`. Run each filter once, then assign by asset ID.
     - `auth_plugins`: the integer IDs of these authentication plugins present on the asset. Success: 141118, 110095, 97993, 12634, 22869 (SSH), 10394, 10400, 20811, 24269 (Windows). Failure: 104410, 110385, 21745, 117885, 24786, 10428, 26917. Make one `tenable_one_search_findings` call per plugin ID, with `finding_detection_id` `contains` a single value (one plugin ID per call) and the `finding_severity` `=` `INFO` filter from step 3. Page with `offset`, then keep only findings whose name starts with that plugin's name below (`contains` also matches longer IDs and CVE names). 141118 Target Credential Status by Authentication Protocol - Valid Credentials Provided; 110095 Target Credential Issues by Authentication Protocol - No Issues Found; 97993 OS Identification and Installed Software Enumeration over SSH v2; 12634 Authenticated Check : OS Name and Installed Package Enumeration; 22869 Software Enumeration (SSH); 10394 Microsoft Windows SMB Log In Possible; 10400 Microsoft Windows SMB Registry Remotely Accessible; 20811 Microsoft Windows Installed Software Enumeration (credentialed check); 24269 WMI Available; 104410 Target Credential Status by Authentication Protocol - Failure for Provided Credentials; 110385 Target Credential Issues by Authentication Protocol - Insufficient Privilege; 21745 OS Security Patch Assessment Failed; 117885 Target Credential Issues by Authentication Protocol - Intermittent Authentication Failure; 24786 Nessus Windows Scan Not Performed with Admin Privileges; 10428 Microsoft Windows SMB Registry Not Fully Accessible Detection; 26917 Microsoft Windows SMB Registry : Nessus Cannot Access the Windows Registry. **Record the IDs only, never the plugin output.** Authentication plugin output holds account names and login methods; do not read it, copy it or print it.
     - `http_service`: `true` when plugin 10107 is present on the asset, otherwise `null`. Never write `false`: the skill records only that 10107 is present. A host with `null` ranks Fix SOON only when every PHP install on it is command-line, its plugin output is complete and it has no WAS finding; otherwise it counts as serving web requests. Find it the same way as the authentication plugins, with the same INFO filter.
     - `unpatched_scan`: the setting belongs to the scan policy, so the skill reads 19506 per scan run. The skill reads 19506 through `workbenches_get_vulnerability_outputs`, which groups outputs by host. `workbenches_get_vulnerability_outputs(19506)` returns each output as a `Hosts:` block (lines like `Hostname: …, Asset ID: …, IPv4: …, First Seen: …, Last Seen: <ISO timestamp>`) followed by a `Plugin Output:` block that holds `Scan name : …`, `Scan policy used : …` and `Scan for Unpatched Vulnerabilities : yes` or `: no`. Read `age` 1, 7, 14, 30, 90, 180 and 365 in order, and stop at the first window that holds the host's own output. If no window holds it, apply rule 2 across all the outputs read. Each window returns only its first 10 outputs and the wide windows mostly repeat the same ones, so on a large tenant expect rule 2 to decide for most hosts. Unlike the other output plugins, 19506 is not gated on the "... and N more outputs" marker. Use the first rule that applies:
       1. The host's own output: a host line whose `Asset ID` is this asset.
       2. Otherwise, hosts scanned by the same scan job share the exact same `Last Seen` timestamp. Take the host's `Last Seen` from `workbenches_get_asset_info` (the "Last Seen" under "Scan Information", not "Last Authenticated Scan"), and use any 19506 output whose host line has a `Last Seen` exactly equal to it. When several outputs match they must all give the same value; if they disagree, write `null`.
       3. Otherwise `null`.
       Set `true` for `yes` and `false` for `no`. **Keep only the `Scan for Unpatched Vulnerabilities` line.** The output can contain the scan account name, so treat it like authentication plugin output: never copy, quote or print any other line of it.
     - `owner_tag`: write `null` here; step 5 updates `assets.json` once the owner is settled.
   *Done when both files exist and every `asset_id` in `findings.json` is a key in `assets.json`.*

5. **Owner.** Resolved in this order, and the scripts apply it:
   - **Owner file (optional).** A CSV the user exports from a CMDB or spreadsheet. Ask once whether they have one; remember the path in `~/Dev/php2shell-reports/config.json`, whose keys are `{"owner_file": <path or null>, "owner_tag_category": <name or null>}`. It needs an `owner` column and at least one of `asset_id`, `hostname`, `fqdn` or `ip`. Headers are case-insensitive, the file is UTF-8 (a BOM is fine), matching ignores case, the first non-blank owner wins, and blank owners are ignored. It wins over tags. Pass it to step 7 with `--owners`; when `--owners` is left out, `render.py` uses the `owner_file` saved in `config.json` beside the run folder, and stops with an error naming the file if it has gone or `config.json` cannot be read, so owners are never dropped silently. Then ask the user for the file again.
   - **Tenable tag.** List categories with `tagging_list_tag_categories_and_values` or `tenable_one_search_tags`. If one looks ownership-like (Owner, Team, Business Unit, App Owner), ask the user to confirm it, or to choose between several, and remember the category name as `owner_tag_category` in `config.json`. Then, per tag value, find its assets with `tenable_one_search_assets` using the `tag` parameter and update that asset's `owner_tag` in `assets.json` to `{"category": "<category>", "value": "<value>"}`.
   - Otherwise the host shows as unassigned.
   Reuse the remembered settings on later runs; ask only when none exist or the file has gone.
   *Done when the owner file path is settled (or skipped) and `owner_tag` is set where a tag applies.*

6. **Fetch vendor advisories.** Run `python3 <this skill's directory>/fetch_advisories.py <run folder>`. It makes public GET requests to OSV.dev, Red Hat's CSAF VEX and the Alpine secdb, writes `advisories/index.json` and one file per response, and prints one `source=… cve=… status=…` line per feed. It exits 0 even when feeds fail. Report any `status=failed` line to the user: the affected installs are then judged without that feed, and never marked Patched.
   *Done when `advisories/index.json` exists and every failed feed is noted for the summary.*

7. **Render.** Run `python3 <this skill's directory>/render.py <run folder>`, adding `--owners <owner file>` when the user has one. It works offline and writes `action-plan.json`, `report.csv`, `report.html`, `auth-followup.txt` and `report.pdf`. The PDF needs Chrome or Chromium; without one the script prints a `WARN` line and skips the PDF. It prints `items=<n> verify_first=<n> assets=<n>`, the count per bucket, and a `feed_failed=` line for each failed feed.
   *Done when the files exist and `items=` plus `verify_first=` match what you expect from step 3 (every host with an active vulnerable or unverifiable PHP install is in one of the two).*

8. **Summarize** in the chat, in this order:
   - One plain sentence on credentials, first, when any PHP host lacks working credentials: for example "41 of 120 PHP hosts weren't scanned with working credentials, so their backport status can't be verified. Configure credentialed scans and rescan."
   - Counts per bucket: Fix FIRST, Fix NEXT, Fix SOON, Verify first.
   - The top Fix FIRST items, each with its owner and action.
   - The Verify first counts with their next steps.
   - Hosts whose credentials failed, grouped by failing plugin, each group with one example host and `analyze auth failures on <asset id>`, plus the [Auth Failure Analyzer](https://exchange.tenable.com/skills/auth-failure-analyzer/) listing, which carries the install steps. This skill never runs the Analyzer. Hosts with no credentials get "configure credentials and rescan" instead. The full list is in `auth-followup.txt`.
   - Failed advisory feeds.
   - When `unpatched_scan` is `false` on any host (the report also carries a run-level note): "Turn on Scan for Unpatched Vulnerabilities in the scan policy so Tenable can report packages with no vendor fix."
   - Hosts flagged as possibly having more PHP installs than the skill read (it reads up to about 500 characters of each plugin output).
   - The interim mitigations from `faq.json` (or the defaults): `memory_limit=-1`, `session.upload_progress.enabled=0`, `fatal_error_backtraces=0` on PHP 8.5, then restart every PHP worker. These reduce exposure but do not fix it, so the patch is still required.
   - The paths of the files written, and a link to the FAQ.

## Known limits

State these when they apply; each is something the user can configure or check.

- Hosts scanned without working credentials can't be verified; rescan with credentials.
- The skill reads up to about 500 characters of each plugin output, so for a host with three or more PHP installs it may see only the first ones; the report flags these hosts.
- The skill reads no vendor feed for Oracle Linux, Amazon Linux, CentOS or Fedora; those hosts rely on Tenable's plugins and can reach Likely patched, not Patched.
- Vendor data can be wrong; vendor "not affected" claims are recorded, not trusted alone.
- Turn on Scan for Unpatched Vulnerabilities in the scan policy so Tenable can report packages with no vendor fix.
