#!/usr/bin/env python3
"""spf-tree: expand an SPF record recursively and count DNS lookups the way
RFC 7208 section 4.6.4 does. MIT licence. https://faultypacket.co.uk
"""
import argparse, csv, datetime as dt, ipaddress, json, re, sys
import urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor

import dns.exception, dns.resolver

__version__ = "1.0.0"
LOOKUP_LIMIT = 10   # RFC 7208 4.6.4: DNS-querying terms per evaluation (MUST)
VOID_LIMIT = 2      # RFC 7208 4.6.4: void lookups (SHOULD)
MX_LIMIT = 10       # RFC 7208 4.6.4: MX records per mx term (MUST, else permerror)
PTR_LIMIT = 10      # RFC 7208 4.6.4: PTR names used per ptr term (extras ignored)
MECHANISMS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}
DOH_TYPES = {"A": 1, "MX": 15, "TXT": 16, "AAAA": 28}


# --------------------------------------------------------------------- DNS
def parse_txt_presentation(s):
    """Concatenate the character-strings of one TXT RR in presentation form
    ('"v=spf1 a" " -all"'), handling backslash escapes. Unquoted -> as is."""
    s = s.strip()
    if not s.startswith('"'):
        return s
    out, i, inq = [], 0, False
    while i < len(s):
        c = s[i]
        if c == '"':
            inq = not inq
        elif inq and c == "\\" and i + 1 < len(s):
            if s[i + 1:i + 4].isdigit() and len(s[i + 1:i + 4]) == 3:
                out.append(chr(int(s[i + 1:i + 4]))); i += 3
            else:
                out.append(s[i + 1]); i += 1
        elif inq:
            out.append(c)
        i += 1
    return "".join(out)


class Resolver:
    """query(name, rtype) -> (values, status); status is ok | void | error:<why>.
    void = NXDOMAIN or NOERROR with no answer of the asked type (RFC 7208 4.6.4).
    TXT values are returned with their character-strings already concatenated."""

    def __init__(self, nameserver=None, timeout=5.0, doh=None):
        self.doh, self.timeout = doh, timeout
        self.r = dns.resolver.Resolver()
        if nameserver:
            self.r.nameservers = [nameserver]
        self.r.lifetime = timeout

    @property
    def servers(self):
        return [self.doh] if self.doh else list(self.r.nameservers)

    def query(self, name, rtype):
        return self._doh(name, rtype) if self.doh else self._dns(name, rtype)

    def _dns(self, name, rtype):
        try:
            ans = self.r.resolve(name, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return [], "void"
        except dns.exception.DNSException as e:
            return [], "error:" + type(e).__name__
        if rtype == "TXT":
            return [b"".join(r.strings).decode("utf-8", "replace") for r in ans], "ok"
        return [r.to_text() for r in ans], "ok"

    def _doh(self, name, rtype):
        url = self.doh + "?" + urllib.parse.urlencode({"name": name, "type": rtype})
        try:
            req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
            with urllib.request.urlopen(req, timeout=self.timeout) as f:
                j = json.load(f)
        except Exception as e:
            return [], "error:" + type(e).__name__
        if j.get("Status") == 3:
            return [], "void"
        if j.get("Status") != 0:
            return [], f"error:rcode{j.get('Status')}"
        data = [a["data"] for a in j.get("Answer", []) if a.get("type") == DOH_TYPES[rtype]]
        if rtype == "TXT":
            data = [parse_txt_presentation(d) for d in data]
        return (data, "ok") if data else ([], "void")


def get_spf(res, domain):
    """RFC 7208 4.5: records starting 'v=spf1' (case-insensitive) then space or end."""
    txts, status = res.query(domain, "TXT")
    recs = [t.strip() for t in txts
            if re.match(r"(?i)^v=spf1( |$)", t.strip())]
    return recs, status


# ------------------------------------------------------------------ parsing
def parse_term(term):
    """-> (kind, name, arg, cidr, qualifier). RFC 7208 4.6.1 / 12."""
    qual = "+"
    if term[0] in "+-~?":
        qual, term = term[0], term[1:]
    m = re.match(r"^([A-Za-z][A-Za-z0-9_.-]*)=(.*)$", term)
    if m:
        return "modifier", m.group(1).lower(), m.group(2), None, qual
    m = re.match(r"^([A-Za-z][A-Za-z0-9_.-]*)(.*)$", term)
    if not m:
        return "invalid", term, None, None, qual
    name, rest = m.group(1).lower(), m.group(2)
    arg = cidr = None
    if name in ("ip4", "ip6"):
        return "mechanism", name, rest[1:] if rest.startswith(":") else None, None, qual
    if rest.startswith(":"):
        rest = rest[1:]
        # domain-spec then optional dual-cidr; macros may contain '/' only inside %{...}
        cm = re.search(r"(/\d+)?(//\d+)?$", rest) if name in ("a", "mx") else None
        if cm and cm.group(0):
            arg, cidr = rest[:cm.start()], cm.group(0)
        else:
            arg = rest
        if arg == "":
            return "invalid", term, None, None, qual
    elif rest:
        if name in ("a", "mx") and re.fullmatch(r"(/\d+)?(//\d+)?", rest):
            cidr = rest
        else:
            return "invalid", term, None, None, qual
    return "mechanism", name, arg, cidr, qual


def valid_cidr(cidr):
    if not cidr:
        return True
    m = re.fullmatch(r"(?:/(\d+))?(?://(\d+))?", cidr)
    return bool(m) and (m.group(1) is None or int(m.group(1)) <= 32) and \
        (m.group(2) is None or int(m.group(2)) <= 128)


def valid_ip(name, arg):
    try:
        net = ipaddress.ip_network(arg, strict=False)
    except (ValueError, TypeError):
        return False
    return net.version == (4 if name == "ip4" else 6)


# ---------------------------------------------------------------- expansion
class Expander:
    def __init__(self, res):
        self.res, self.lookups, self.voids = res, 0, 0
        self.issues, self.rows, self.seen = [], [], {}

    def issue(self, sev, code, msg):
        self.issues.append({"severity": sev, "code": code, "message": msg})

    def count(self, path, term, status):
        """One DNS-querying term (RFC 7208 4.6.4)."""
        self.lookups += 1
        void = status == "void"
        self.voids += void
        self.rows.append({"lookup_no": self.lookups, "path": path, "term": term,
                          "void": void, "status": status})
        if self.lookups == LOOKUP_LIMIT + 1:
            self.issue("permerror", "lookup_limit",
                       f"more than {LOOKUP_LIMIT} DNS-querying terms; exceeded at '{term}' ({path})")
        if void and self.voids == VOID_LIMIT + 1:
            self.issue("permerror", "void_limit",
                       f"more than {VOID_LIMIT} void lookups; exceeded at '{term}' ({path})")
        if status.startswith("error"):
            self.issue("temperror", "dns_error", f"'{term}' ({path}): DNS {status}")

    def expand(self, domain, stack=(), qualifier="+", via="root"):
        domain = domain.rstrip(".").lower()
        node = {"domain": domain, "via": via, "qualifier": qualifier, "record": None,
                "lookups_subtree": 0, "children": []}
        path = " > ".join(list(stack) + [domain])
        start = self.lookups
        if stack:  # the TXT fetch of an include/redirect target is the counted lookup
            recs, status = get_spf(self.res, domain)
            self.count(" > ".join(stack), f"{via}:{domain}", status)
        else:
            recs, status = get_spf(self.res, domain)
        if domain in stack:
            self.issue("permerror", "loop", f"loop: {path}")
            node["error"] = "loop"
            node["lookups_subtree"] = self.lookups - start
            return node
        if domain in self.seen:
            self.issue("warning", "duplicate", f"{domain} evaluated more than once (via {path})")
            node["duplicate"] = True
        self.seen[domain] = self.seen.get(domain, 0) + 1
        if status.startswith("error"):
            node["error"] = status
            if not stack:
                self.issue("temperror", "dns_error", f"{domain}: DNS {status}")
            node["lookups_subtree"] = self.lookups - start
            return node
        if not recs:
            node["error"] = "no SPF record"
            if stack:  # RFC 7208 5.2 (include) / 6.1 (redirect): permerror
                self.issue("permerror", "missing_record",
                           f"{domain}: no SPF record at {via} target ({path})")
            else:
                self.issue("none", "no_record", f"{domain}: no SPF record published")
            node["lookups_subtree"] = self.lookups - start
            return node
        if len(recs) > 1:  # RFC 7208 4.5
            self.issue("permerror", "multiple_records", f"{domain}: {len(recs)} SPF records")
            node["records"] = recs
        rec = recs[0]
        node["record"] = rec
        terms = rec.split()[1:]
        mods = {}
        has_all = False
        for term in terms:
            kind, name, arg, cidr, qual = parse_term(term)
            if kind == "invalid" or (kind == "mechanism" and name not in MECHANISMS):
                self.issue("permerror", "syntax", f"{domain}: invalid or unknown term '{term}'")
                continue
            if kind == "modifier":
                if name in ("redirect", "exp"):
                    if name in mods:  # RFC 7208 6
                        self.issue("permerror", "duplicate_modifier",
                                   f"{domain}: '{name}' appears more than once")
                    mods.setdefault(name, arg)
                if "%" in arg:
                    self.issue("info", "macro", f"{domain}: macro in '{term}'")
                continue
            if name == "all":
                has_all = True
            elif name in ("ip4", "ip6"):
                if not valid_ip(name, arg):
                    self.issue("permerror", "syntax", f"{domain}: invalid address in '{term}'")
            elif name in ("include", "exists") and not arg:  # RFC 7208 5.2, 5.7
                self.issue("permerror", "syntax", f"{domain}: '{term}' needs a domain")
            elif arg and "%" not in arg and not re.fullmatch(
                    r"(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z0-9-]+\.?", arg):
                self.issue("permerror", "syntax", f"{domain}: invalid domain in '{term}'")  # RFC 7208 7.1
            elif not valid_cidr(cidr):
                self.issue("permerror", "syntax", f"{domain}: invalid CIDR length in '{term}'")
            elif arg and "%" in arg:
                # RFC 7208 7: macros expand per message; we never guess an expansion
                self.issue("info", "macro",
                           f"{domain}: macro in '{term}'; counted as 1 lookup, not resolved")
                self.count(path, term, "dynamic")
            elif name == "include":
                node["children"].append(self.expand(arg, tuple(stack) + (domain,), qual, "include"))
            elif name == "exists":
                _, st = self.res.query(arg, "A")  # RFC 7208 5.7: always A
                self.count(path, term, st)
            elif name == "ptr":
                self.issue("warning", "ptr", f"{domain}: 'ptr' is deprecated (RFC 7208 5.5); "
                           f"its cost depends on the sender IP, counted as 1")
                self.count(path, term, "dynamic")
            elif name == "a":
                target = arg or domain
                vals, st = self.res.query(target, "A")
                vals6, st6 = self.res.query(target, "AAAA")
                # a receiver queries A or AAAA per the sender's IP family; void only if both are
                if st == "ok" or st6 == "ok":
                    st = "ok"
                elif st.startswith("error") or st6.startswith("error"):
                    st = st if st.startswith("error") else st6
                self.count(path, term, st)
            elif name == "mx":
                target = arg or domain
                mx, st = self.res.query(target, "MX")
                self.count(path, term, st)
                if len(mx) > MX_LIMIT:
                    self.issue("permerror", "mx_limit",
                               f"{domain}: '{term}' returns {len(mx)} MX records (> {MX_LIMIT})")
        if "redirect" in mods:
            if has_all:  # RFC 7208 6.1
                self.issue("info", "redirect_ignored",
                           f"{domain}: redirect ignored because 'all' is present")
            elif "%" in mods["redirect"]:
                self.count(path, "redirect=" + mods["redirect"], "dynamic")
            else:
                node["children"].append(
                    self.expand(mods["redirect"], tuple(stack) + (domain,), "+", "redirect"))
        node["lookups_subtree"] = self.lookups - start
        return node


def verdict(issues):
    sevs = {i["severity"] for i in issues}
    for v in ("permerror", "temperror", "none"):
        if v in sevs:
            return v
    return "ok"


def analyse(domain, res):
    e = Expander(res)
    tree = e.expand(domain)
    return {"domain": domain, "lookups": e.lookups, "lookup_limit": LOOKUP_LIMIT,
            "void_lookups": e.voids, "void_limit": VOID_LIMIT,
            "result": verdict(e.issues), "issues": e.issues,
            "lookup_log": e.rows, "tree": tree}


# -------------------------------------------------------------------- input
def extract_domain(raw):
    """URL, email, host:port or bare name -> lowercase ASCII (IDNA) domain.
    Raises ValueError."""
    s = raw.strip()
    if not s:
        raise ValueError("empty")
    if "://" in s:
        s = urllib.parse.urlsplit(s).netloc
    s = s.split("/")[0].split("?")[0].split("#")[0]
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    if s.startswith("["):
        raise ValueError("IP literal, not a domain")
    s = s.split(":")[0].rstrip(".").strip().lower()
    if not s:
        raise ValueError("no host")
    try:
        ipaddress.ip_address(s)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        raise ValueError("IP address, not a domain")
    try:
        s = s.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("invalid IDN")
    labels = s.split(".")
    if len(s) > 253 or len(labels) < 2 or not all(
            re.fullmatch(r"(?!-)[a-z0-9_-]{1,63}(?<!-)", l) for l in labels):
        raise ValueError("not a valid domain name")
    return s


def read_lines(lines):
    out = []
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def collect(args_domains, files, stdin, auto_stdin=False):
    """-> (domains in first-seen order, deduped; list of {input, error}).
    stdin is read for '-' in files, or when auto_stdin and it is not a TTY."""
    raw = list(args_domains)
    for f in files or []:
        if f == "-":
            raw += read_lines(stdin)
        else:
            with open(f, encoding="utf-8") as fh:
                raw += read_lines(fh)
    if auto_stdin and stdin is not None and not stdin.isatty():
        raw += read_lines(stdin)
    seen, domains, bad = set(), [], []
    for r in raw:
        try:
            d = extract_domain(r)
        except ValueError as e:
            bad.append({"input": r, "error": str(e)})
            continue
        if d not in seen:
            seen.add(d); domains.append(d)
    return domains, bad


# ------------------------------------------------------------------- output
def render(node, indent=0, out=None):
    out = [] if out is None else out
    pad = "  " * indent
    q = "" if node["qualifier"] == "+" else " " + node["qualifier"]
    bits = [f"lookups: {node['lookups_subtree']}"]
    if node.get("duplicate"):
        bits.append("DUPLICATE")
    if node.get("error"):
        bits.append("ERROR: " + node["error"])
    out.append(f"{pad}{node['domain']} [{node['via']}{q}] ({', '.join(bits)})")
    if node.get("record"):
        out.append(f"{pad}  \u2514 {node['record']}")
    for c in node["children"]:
        render(c, indent + 1, out)
    return out


def run_one(domain, res):
    checked = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    try:
        r = analyse(domain, res)
    except Exception as e:  # isolate per-domain failures in a batch
        r = {"domain": domain, "lookups": None, "lookup_limit": LOOKUP_LIMIT,
             "void_lookups": None, "void_limit": VOID_LIMIT, "result": "error",
             "issues": [{"severity": "error", "code": "internal",
                         "message": f"{type(e).__name__}: {e}"}],
             "lookup_log": [], "tree": None}
    return {"tool": "spf-tree", "version": __version__, "checked_at_utc": checked,
            "resolvers": res.servers, **r}


def summary_table(results):
    w = max([6] + [len(r["domain"]) for r in results])
    lines = [f"{'domain':<{w}}  lookups  void  result     issues"]
    for r in results:
        lk = "-" if r["lookups"] is None else f"{r['lookups']}/{LOOKUP_LIMIT}"
        vd = "-" if r["void_lookups"] is None else f"{r['void_lookups']}/{VOID_LIMIT}"
        n = sum(i["severity"] != "info" for i in r["issues"])
        lines.append(f"{r['domain']:<{w}}  {lk:>7}  {vd:>4}  {r['result']:<9}  {n}")
    return lines


def main(argv=None, stdin=None):
    stdin = sys.stdin if stdin is None else stdin
    p = argparse.ArgumentParser(prog="spf_tree.py",
        description="Expand SPF records and count DNS lookups (RFC 7208 4.6.4).")
    p.add_argument("domains", nargs="*", help="domains, URLs or email addresses")
    p.add_argument("-f", "--file", action="append", help="file with one input per line ('-' = stdin); repeatable")
    p.add_argument("--json", help="write JSON array (one object per domain) to file, '-' for stdout")
    p.add_argument("--csv", help="write one summary row per domain to this CSV file")
    p.add_argument("--lookups-csv", help="write one row per counted lookup to this CSV file")
    p.add_argument("--resolver", help="nameserver IP to use (port 53)")
    p.add_argument("--doh", action="store_true", help="use a DNS-over-HTTPS JSON API instead of port 53")
    p.add_argument("--doh-url", default="https://dns.google/resolve", help="DoH JSON endpoint (default %(default)s)")
    p.add_argument("--timeout", type=float, default=5.0, help="per-query timeout, seconds (default 5)")
    p.add_argument("-c", "--concurrency", type=int, default=8, help="domains checked in parallel (default 8, max 64)")
    p.add_argument("-q", "--quiet", action="store_true", help="summary table only, no trees")
    p.add_argument("--version", action="version", version=f"spf-tree {__version__}")
    a = p.parse_args(argv)
    if not 1 <= a.concurrency <= 64:
        p.error("--concurrency must be 1..64")
    try:
        domains, bad = collect(a.domains, a.file, stdin, auto_stdin=not a.domains and not a.file)
    except OSError as e:
        p.error(str(e))
    for b in bad:
        print(f"skipped input {b['input']!r}: {b['error']}", file=sys.stderr)
    if not domains:
        p.error("no valid domains given")
    res = Resolver(a.resolver, a.timeout, a.doh_url if a.doh else None)
    with ThreadPoolExecutor(max_workers=min(a.concurrency, len(domains))) as ex:
        results = list(ex.map(lambda d: run_one(d, res), domains))
    out = sys.stderr if a.json == "-" else sys.stdout
    if not a.quiet:
        for r in results:
            if r["tree"]:
                print("\n".join(render(r["tree"])), file=out)
            for i in r["issues"]:
                print(f"   [{i['severity']}] {i['message']}", file=out)
            print(file=out)
    print("\n".join(summary_table(results)), file=out)
    print(f"checked {results[0]['checked_at_utc']} via {','.join(res.servers)}", file=out)
    if a.json:
        data = json.dumps(results, indent=2)
        if a.json == "-":
            sys.stdout.write(data + "\n")
        else:
            with open(a.json, "w") as f:
                f.write(data + "\n")
    if a.csv:
        with open(a.csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["checked_at_utc", "domain", "result", "lookups", "void_lookups",
                        "issues", "resolver"])
            for r in results:
                w.writerow([r["checked_at_utc"], r["domain"], r["result"], r["lookups"],
                            r["void_lookups"],
                            " | ".join(f"{i['severity']}:{i['code']}" for i in r["issues"]),
                            ",".join(r["resolvers"])])
    if a.lookups_csv:
        with open(a.lookups_csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["checked_at_utc", "domain", "lookup_no", "path", "term", "void", "status"])
            for r in results:
                for row in r["lookup_log"]:
                    w.writerow([r["checked_at_utc"], r["domain"], row["lookup_no"], row["path"],
                                row["term"], row["void"], row["status"]])
    return 1 if (bad or any(r["result"] != "ok" for r in results)) else 0


if __name__ == "__main__":
    sys.exit(main())
