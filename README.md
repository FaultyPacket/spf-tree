# spf-tree

Expand an SPF record recursively and count DNS lookups across the whole tree, as RFC 7208 §4.6.4 defines them. Single domain or batch.

Requires Python 3.11+ and dnspython. Runs locally; nothing is uploaded.

## Install

```
git clone https://github.com/FaultyPacket/spf-tree && cd spf-tree
pip install -r requirements.txt
```

## Usage

```
python3 spf_tree.py example.com
python3 spf_tree.py example.com example.org --json out.json --csv out.csv
python3 spf_tree.py -f domains.txt -q                # batch from file
cat domains.txt | python3 spf_tree.py -q             # batch from stdin
python3 spf_tree.py example.com --resolver 9.9.9.9   # specific resolver, port 53
python3 spf_tree.py example.com --doh                # DNS-over-HTTPS JSON (default https://dns.google/resolve)
python3 spf_tree.py example.com --json -             # JSON only on stdout; human output goes to stderr
```

| Option | Meaning |
|---|---|
| `domains…` | Domains, URLs or email addresses |
| `-f, --file FILE` | One input per line; `#` comments and blank lines ignored; `-` = stdin; repeatable |
| `--json FILE` | JSON array, one object per domain (`-` = stdout) |
| `--csv FILE` | One summary row per domain |
| `--lookups-csv FILE` | One row per counted lookup |
| `--resolver IP` | Nameserver for port-53 queries |
| `--doh`, `--doh-url URL` | Use a DoH JSON endpoint instead of port 53 |
| `--timeout S` | Per-query timeout, default 5 |
| `-c, --concurrency N` | Domains checked in parallel, 1–64, default 8 |
| `-q, --quiet` | Summary table only |
| `--version` | Print version |

With no domains and no `--file`, input is read from stdin if it is not a terminal.

**Input normalisation.** Scheme, `user@`, port, path, query and fragment are stripped; the name is lower-cased, a trailing dot removed and IDNs converted to A-labels (Python's IDNA 2003 codec). `www.` is not stripped: the name you give is the name checked. Duplicates are removed (first occurrence kept). Invalid inputs and IP addresses are reported on stderr and skipped; the rest of the batch still runs. One domain failing (DNS error, internal error) never stops the others.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Every domain has result `ok` and every input was valid |
| 1 | Any domain is `permerror`, `temperror`, `none` or `error`, or any input was skipped |
| 2 | Usage error (bad option, unreadable file, no valid domains) |

## Results

| `result` | Meaning |
|---|---|
| `ok` | Record found; no permerror or temperror conditions detected |
| `permerror` | A condition RFC 7208 says yields permerror (see checks) |
| `temperror` | A DNS query failed (timeout, SERVFAIL, etc.) |
| `none` | No SPF record at the domain |
| `error` | The tool itself failed on this domain (reported in `issues`) |

`ok` is a statement about the record's structure, not an SPF `pass`: whether a given sender passes depends on its IP.

## Checks

| Check | Severity | RFC 7208 |
|---|---|---|
| More than 10 DNS-querying terms (`include`, `a`, `mx`, `ptr`, `exists`, `redirect`) across the tree | permerror | §4.6.4 |
| More than 2 void lookups (NXDOMAIN, or NOERROR with no answer) | permerror | §4.6.4 (SHOULD) |
| `mx` returning more than 10 MX records | permerror | §4.6.4 |
| More than one `v=spf1` record | permerror | §4.5 |
| `include` / `redirect` target with no SPF record | permerror | §5.2, §6.1 |
| Unknown mechanism, bad syntax, bad IP or CIDR length, invalid domain | permerror | §5, §7.1, §12 |
| `redirect` or `exp` appearing twice | permerror | §6 |
| Include loop | permerror | §4.6.4 (would exhaust the limit) |
| DNS failure | temperror | §2.6.6 |
| `redirect` ignored because `all` is present | info | §6.1 |
| Same domain evaluated more than once | warning | — |
| `ptr` used (deprecated) | warning | §5.5 |
| Macro in a term (`%{i}` etc.) | info | §7 |

Counting rules applied: `ip4`, `ip6`, `all` and `exp` cost nothing; the initial TXT query for the checked domain is not counted; each `include`/`redirect` costs one plus its subtree. `v=spf1`, mechanism and modifier names, and domain names are case-insensitive (§4.5, §4.6.1). Multi-string TXT records are concatenated without separators (§3.3). `a` and `mx` accept CIDR suffixes (`a:host/24//64`); the suffix is stripped before the query. `exists` queries A only (§5.7).

## Output schema (JSON, per domain)

```
tool, version, checked_at_utc, resolvers[], domain,
lookups, lookup_limit, void_lookups, void_limit, result,
issues[]:     {severity, code, message}
lookup_log[]: {lookup_no, path, term, void, status}   status: ok | void | dynamic | error:<reason>
tree:         {domain, via, qualifier, record, lookups_subtree, children[], [duplicate], [error], [records]}
```

`lookups` and `void_lookups` are `null` when `result` is `error`. CSV columns: `checked_at_utc, domain, result, lookups, void_lookups, issues, resolver`.

## Limitations

- **Worst case, not one message.** Every term is evaluated. A receiver stops at the first match or first permerror, so a real evaluation may use fewer lookups. Over 10 here means some senders will get permerror.
- **Sender-dependent terms are not resolved.** Terms with macros and `ptr` are counted as one lookup each and never expanded, so their void status and any includes behind them are unknown.
- **`a` and void.** A receiver queries A or AAAA depending on the sender's address family. The tool counts `a` as void only when both are empty, so an IPv4-only host can still be void for an IPv6 sender.
- **MX address lookups** (up to 10 per `mx`, §4.6.4) are not performed; only the MX-count limit is checked.
- **Not a full evaluator.** No `check_host()` for a given IP, no `exp` fetching, no DNSSEC validation.
- **Snapshot.** DNS changes; the timestamp and resolver are part of each result. Different resolvers can briefly disagree.
- **Port 53 interception.** Some networks block or rewrite port-53 traffic and return empty answers, which shows up as `none` or void lookups. Use `--doh` there.

## Tests

```
pip install -r requirements-dev.txt
python3 -m pytest -q
```

Offline: a fake resolver covers the counting rules, and dnspython and the DoH client are mocked to test both transport paths.

## More

Free checks, plus a one-off SPF fix pack: https://faultypacket.co.uk

MIT licence. See CHANGELOG.md.
