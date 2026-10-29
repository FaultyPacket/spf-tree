import io, json, os, sys
from unittest import mock
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import spf_tree as S
import dns.resolver, dns.rdata, dns.rdataclass, dns.rdatatype, dns.exception


class FakeRes:
    """zone: {(name, rtype): list | 'nx' | 'err'}; missing -> void."""
    servers = ["fake"]
    def __init__(self, z): self.z, self.q = z, []
    def query(self, name, rtype):
        self.q.append((name, rtype))
        v = self.z.get((name.rstrip(".").lower(), rtype))
        if v == "err": return [], "error:Timeout"
        return (list(v), "ok") if v else ([], "void")


def go(zone, d="example.test"):
    return S.analyse(d, FakeRes(zone))

def codes(r): return {i["code"] for i in r["issues"]}
def spf(s): return [s]


# ---- counting (RFC 7208 4.6.4)
def test_nested_include_counted():
    z = {("example.test","TXT"): spf("v=spf1 include:a.test mx -all"),
         ("a.test","TXT"): spf("v=spf1 include:b.test a ~all"),
         ("b.test","TXT"): spf("v=spf1 ip4:192.0.2.0/24 -all"),
         ("example.test","MX"): ["10 mx.example.test."], ("a.test","A"): ["192.0.2.1"]}
    r = go(z)
    assert (r["lookups"], r["void_lookups"], r["result"]) == (4, 0, "ok")

def test_ip4_ip6_all_exp_cost_nothing():
    r = go({("example.test","TXT"): spf("v=spf1 ip4:192.0.2.1 ip6:2001:db8::/32 exp=e.test -all")})
    assert r["lookups"] == 0 and r["result"] == "ok"

@pytest.mark.parametrize("n,res", [(10, "ok"), (11, "permerror")])
def test_limit_boundary(n, res):
    z = {("example.test","TXT"): spf("v=spf1 " + " ".join(f"include:i{k}.test" for k in range(n)) + " -all")}
    for k in range(n): z[(f"i{k}.test","TXT")] = spf("v=spf1 -all")
    r = go(z)
    assert r["lookups"] == n and r["result"] == res

def test_every_querying_term_counts():
    z = {("example.test","TXT"): spf("v=spf1 a mx ptr exists:x.test include:i.test redirect=ignored.test"),
         ("example.test","A"): ["192.0.2.1"], ("example.test","MX"): ["10 m.test."],
         ("x.test","A"): ["127.0.0.2"], ("i.test","TXT"): spf("v=spf1 -all"),
         ("ignored.test","TXT"): spf("v=spf1 -all")}
    r = go(z)
    assert r["lookups"] == 6  # a mx ptr exists include redirect

# ---- void lookups
def test_void_limit_nxdomain_and_empty():
    r = go({("example.test","TXT"): spf("v=spf1 a:x1.test a:x2.test -all")})
    assert r["void_lookups"] == 2 and "void_limit" not in codes(r)
    r = go({("example.test","TXT"): spf("v=spf1 a:x1.test a:x2.test mx:x3.test -all")})
    assert r["void_lookups"] == 3 and "void_limit" in codes(r) and r["result"] == "permerror"

def test_a_not_void_if_only_aaaa():
    r = go({("example.test","TXT"): spf("v=spf1 a:v6.test -all"), ("v6.test","AAAA"): ["2001:db8::1"]})
    assert r["void_lookups"] == 0

def test_exists_queries_A_only():
    f = FakeRes({("example.test","TXT"): spf("v=spf1 exists:x.test -all"), ("x.test","AAAA"): ["::1"]})
    r = S.analyse("example.test", f)
    assert r["void_lookups"] == 1 and ("x.test","AAAA") not in f.q

# ---- MX / ptr
def test_mx_over_10_permerror():
    z = {("example.test","TXT"): spf("v=spf1 mx -all"),
         ("example.test","MX"): [f"10 m{k}.test." for k in range(11)]}
    assert "mx_limit" in codes(go(z))
    z[("example.test","MX")] = z[("example.test","MX")][:10]
    assert "mx_limit" not in codes(go(z))

def test_ptr_flagged_and_counted():
    r = go({("example.test","TXT"): spf("v=spf1 ptr -all")})
    assert r["lookups"] == 1 and "ptr" in codes(r) and r["result"] == "ok"

# ---- redirect
def test_redirect_followed_without_all():
    r = go({("example.test","TXT"): spf("v=spf1 redirect=r.test"), ("r.test","TXT"): spf("v=spf1 mx -all")})
    assert r["lookups"] == 2 and r["tree"]["children"][0]["via"] == "redirect"

def test_redirect_ignored_with_all():
    f = FakeRes({("example.test","TXT"): spf("v=spf1 ~all redirect=r.test")})
    r = S.analyse("example.test", f)
    assert r["lookups"] == 0 and "redirect_ignored" in codes(r) and ("r.test","TXT") not in f.q

def test_redirect_to_missing_record_permerror():
    r = go({("example.test","TXT"): spf("v=spf1 redirect=r.test")})
    assert "missing_record" in codes(r) and r["result"] == "permerror"

def test_duplicate_redirect_permerror():
    z = {("example.test","TXT"): spf("v=spf1 redirect=a.test redirect=b.test"), ("a.test","TXT"): spf("v=spf1 -all")}
    assert "duplicate_modifier" in codes(go(z))

# ---- records
def test_multiple_spf_records_permerror():
    r = go({("example.test","TXT"): ["v=spf1 -all", "v=spf1 ~all", "google-site-verification=x"]})
    assert "multiple_records" in codes(r) and r["result"] == "permerror"

def test_include_no_record_permerror():
    r = go({("example.test","TXT"): spf("v=spf1 include:gone.test -all"), ("gone.test","TXT"): ["hello"]})
    assert "missing_record" in codes(r) and r["void_lookups"] == 0

def test_include_nxdomain_is_void_and_permerror():
    r = go({("example.test","TXT"): spf("v=spf1 include:gone.test -all")})
    assert r["void_lookups"] == 1 and r["result"] == "permerror"

def test_no_root_record_none():
    assert go({})["result"] == "none"

def test_case_insensitive():
    z = {("example.test","TXT"): spf("V=SPF1 INCLUDE:A.Test MX:Example.TEST/24 -ALL"),
         ("a.test","TXT"): spf("v=spf1 -all"), ("example.test","MX"): ["10 m.test."]}
    r = go(z)
    assert r["lookups"] == 2 and r["result"] == "ok"

def test_spf1_prefix_must_end_or_space():
    assert go({("example.test","TXT"): spf("v=spf10 -all")})["result"] == "none"

def test_txt_multistring_presentation():
    assert S.parse_txt_presentation('"v=spf1 include:a.test" " -all"') == "v=spf1 include:a.test -all"
    assert S.parse_txt_presentation('"a\\"b" "\\065"') == 'a"bA'
    assert S.parse_txt_presentation("v=spf1 -all") == "v=spf1 -all"

def test_loop_detected():
    z = {("example.test","TXT"): spf("v=spf1 include:a.test -all"), ("a.test","TXT"): spf("v=spf1 include:example.test -all")}
    assert "loop" in codes(go(z))

def test_duplicate_include_warned():
    z = {("example.test","TXT"): spf("v=spf1 include:a.test include:b.test -all"),
         ("a.test","TXT"): spf("v=spf1 include:c.test -all"), ("b.test","TXT"): spf("v=spf1 include:c.test -all"),
         ("c.test","TXT"): spf("v=spf1 -all")}
    r = go(z)
    assert "duplicate" in codes(r) and r["lookups"] == 4 and r["result"] == "ok"

def test_dns_error_temperror():
    r = go({("example.test","TXT"): spf("v=spf1 mx -all"), ("example.test","MX"): "err"})
    assert r["result"] == "temperror"
    assert go({("example.test","TXT"): "err"})["result"] == "temperror"

# ---- macros: flagged, counted, never expanded
def test_macros_not_expanded():
    f = FakeRes({("example.test","TXT"): spf("v=spf1 exists:%{i}.%{d}.x.test include:%{d2}.y.test -all")})
    r = S.analyse("example.test", f)
    assert r["lookups"] == 2 and "macro" in codes(r)
    assert all("%" not in n for n, _ in f.q)

def test_macro_redirect_not_expanded():
    f = FakeRes({("example.test","TXT"): spf("v=spf1 redirect=%{d}._spf.test")})
    r = S.analyse("example.test", f)
    assert r["lookups"] == 1 and all("%" not in n for n, _ in f.q)

# ---- parsing / syntax
@pytest.mark.parametrize("term,exp", [
    ("a", ("mechanism","a",None,None,"+")),
    ("-a/24", ("mechanism","a",None,"/24","-")),
    ("a//64", ("mechanism","a",None,"//64","+")),
    ("a:h.test/24//64", ("mechanism","a","h.test","/24//64","+")),
    ("~mx:m.test/28", ("mechanism","mx","m.test","/28","~")),
    ("ip6:2001:db8::/32", ("mechanism","ip6","2001:db8::/32",None,"+")),
    ("include:_spf.x.test", ("mechanism","include","_spf.x.test",None,"+")),
    ("Redirect=r.test", ("modifier","redirect","r.test",None,"+")),
])
def test_parse_term(term, exp):
    assert S.parse_term(term) == exp

def test_cidr_on_a_queries_bare_host():
    f = FakeRes({("example.test","TXT"): spf("v=spf1 a:h.test/24 mx/28 -all"),
                 ("h.test","A"): ["192.0.2.1"], ("example.test","MX"): ["10 m.test."]})
    r = S.analyse("example.test", f)
    assert ("h.test","A") in f.q and ("example.test","MX") in f.q and r["void_lookups"] == 0

@pytest.mark.parametrize("bad", ["a/33", "a//129", "ip4:999.1.1.1", "ip4:2001:db8::1", "ip6:192.0.2.1",
                                 "foo:bar", "include", "include:", "exists", "a:/24x"])
def test_syntax_errors(bad):
    assert "syntax" in codes(go({("example.test","TXT"): spf("v=spf1 " + bad + " -all")}))

def test_unknown_modifier_ignored():
    assert go({("example.test","TXT"): spf("v=spf1 foo=bar -all")})["result"] == "ok"

# ---- port-53 path (dnspython mocked)
def _rr(rtype, *texts):
    return [dns.rdata.from_text(dns.rdataclass.IN, getattr(dns.rdatatype, rtype), t) for t in texts]

def test_port53_path():
    answers = {("example.test","TXT"): _rr("TXT", '"v=spf1 include:a.test" " mx -all"', '"unrelated"'),
               ("a.test","TXT"): _rr("TXT", '"v=spf1 -all"'),
               ("example.test","MX"): _rr("MX", "10 m.test.")}
    def fake(self, name, rtype, *a, **k):
        if name == "nx.test": raise dns.resolver.NXDOMAIN()
        if name == "slow.test": raise dns.exception.Timeout()
        if (name, rtype) in answers: return answers[(name, rtype)]
        raise dns.resolver.NoAnswer()
    with mock.patch.object(dns.resolver.Resolver, "resolve", fake):
        res = S.Resolver("192.0.2.53")
        assert res.servers == ["192.0.2.53"]
        assert S.get_spf(res, "example.test") == (["v=spf1 include:a.test mx -all"], "ok")
        assert res.query("nx.test", "A") == ([], "void")
        assert res.query("example.test", "AAAA") == ([], "void")
        assert res.query("slow.test", "A") == ([], "error:Timeout")
        r = S.analyse("example.test", res)
        assert (r["lookups"], r["result"]) == (2, "ok")

def test_doh_path():
    replies = {"TXT": {"Status": 0, "Answer": [{"type": 5, "data": "x."}, {"type": 16, "data": '"v=spf1 " "-all"'}]},
               "A": {"Status": 3}, "MX": {"Status": 0}, "AAAA": {"Status": 2}}
    def fake_open(req, timeout):
        rtype = req.full_url.split("type=")[1]
        return io.BytesIO(json.dumps(replies[rtype]).encode())
    with mock.patch("urllib.request.urlopen", fake_open):
        res = S.Resolver(doh="https://doh.invalid/resolve")
        assert res.query("x.test", "TXT") == (["v=spf1 -all"], "ok")
        assert res.query("x.test", "A") == ([], "void")
        assert res.query("x.test", "MX") == ([], "void")
        assert res.query("x.test", "AAAA") == ([], "error:rcode2")

# ---- batch input
@pytest.mark.parametrize("raw,exp", [
    ("Example.COM", "example.com"), ("example.com.", "example.com"),
    ("https://user:pw@www.Example.com:8443/path?q=1#f", "www.example.com"),
    ("http://example.com", "example.com"), ("postmaster@Example.org", "example.org"),
    ("mailto:a@b.example.net", "b.example.net"), ("example.com:25", "example.com")("example.com/foo", "example.com"), ("bücher.example", "xn--bcher-kva.example"),
    ("_dmarc.example.com", "_dmarc.example.com"),
])
def test_extract_domain(raw, exp):
    assert S.extract_domain(raw) == exp

@pytest.mark.parametrize("raw", ["", "localhost", "192.0.2.1", "[2001:db8::1]", "-bad-.com", "a..b", "x" * 64 + ".com"])
def test_extract_domain_rejects(raw):
    with pytest.raises(ValueError):
        S.extract_domain(raw)

def test_collect_file_comments_dedupe(tmp_path):
    p = tmp_path / "d.txt"
    p.write_text("# list\nexample.com\n\n  EXAMPLE.com  # dup\nhttps://example.org/x\nbob@example.org\nexample.net\nnot_a_domain\n")
    doms, bad = S.collect(["example.net"], [str(p)], None)
    assert doms == ["example.net", "example.com", "example.org"]
    assert [b["input"] for b in bad] == ["not_a_domain"]

def test_collect_stdin():
    s = io.StringIO("a.example\nb.example\n")
    assert S.collect([], ["-"], s)[0] == ["a.example", "b.example"]
    s = io.StringIO("c.example\n"); s.isatty = lambda: False
    assert S.collect([], None, s, auto_stdin=True)[0] == ["c.example"]

def _zone_res(zone):
    f = FakeRes(zone)
    return mock.patch.object(S, "Resolver", lambda *a, **k: f)

def test_batch_error_isolation_and_outputs(tmp_path, capsys):
    zone = {("good.test","TXT"): spf("v=spf1 -all")}
    real = S.analyse
    def flaky(d, res):
        if d == "boom.test": raise RuntimeError("kaboom")
        return real(d, res)
    j, c, l = tmp_path / "o.json", tmp_path / "o.csv", tmp_path / "l.csv"
    with _zone_res(zone), mock.patch.object(S, "analyse", flaky):
        rc = S.main(["good.test", "boom.test", "none.test", "GOOD.test", "-c", "3", "-q",
                     "--json", str(j), "--csv", str(c), "--lookups-csv", str(l)])
    assert rc == 1
    data = json.loads(j.read_text())
    assert [d["domain"] for d in data] == ["good.test", "boom.test", "none.test"]
    assert [d["result"] for d in data] == ["ok", "error", "none"]
    assert data[0]["version"] == "1.0.0" and data[0]["checked_at_utc"].endswith("+00:00")
    assert len(c.read_text().strip().splitlines()) == 4
    out = capsys.readouterr().out
    assert "good.test" in out and "error" in out

def test_exit_zero_when_all_ok(capsys):
    with _zone_res({("good.test","TXT"): spf("v=spf1 -all")}):
        assert S.main(["good.test", "-q"]) == 0

def test_bad_input_sets_exit_1_but_runs_rest(capsys):
    with _zone_res({("good.test","TXT"): spf("v=spf1 -all")}):
        assert S.main(["good.test", "192.0.2.1", "-q"]) == 1
    assert "skipped input" in capsys.readouterr().err

def test_json_stdout_is_pure_json(capsys):
    with _zone_res({("good.test","TXT"): spf("v=spf1 -all")}):
        S.main(["good.test", "--json", "-"])
    assert json.loads(capsys.readouterr().out)[0]["domain"] == "good.test"

def test_usage_errors():
    for argv in (["-c", "0", "x.test"], ["--file", "/nonexistent/file"]):
        with pytest.raises(SystemExit) as e:
            S.main(argv, stdin=io.StringIO(""))
        assert e.value.code == 2
    with pytest.raises(SystemExit) as e:
        S.main(["--version"])
    assert e.value.code == 0

def test_reject_messages():
    for raw, msg in [("192.0.2.1", "IP address"), ("not a domain!", "not a valid domain")]:
        with pytest.raises(ValueError, match=msg):
            S.extract_domain(raw)
