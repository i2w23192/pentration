"""Offline unit tests for allscan.

These tests never touch the network: the engine tests patch the module
registry with in-memory stubs, and everything else exercises pure data/logic
(models, reporting, diffing, config, validation, secret scanning).

Run with:  pytest -q
"""

from __future__ import annotations

from pathlib import Path

import pytest

import allscan.engine as engine_mod
from allscan.base import Module
from allscan.config import Config
from allscan.engine import Engine
from allscan.models import Category, Finding, ScanResult, Severity
from allscan.utils import (
    RateLimiter,
    ScanCancelled,
    normalize_target,
    scan_for_secrets,
    validate_target,
)
from allscan import report


# --------------------------------------------------------------------------- #
# stub modules (no network)
# --------------------------------------------------------------------------- #


class StubRecon(Module):
    name = "recon"
    label = "recon"

    def run(self, ctx):
        ctx.log("discovering")
        ctx.state["hosts"] = {"a.example.test": ["203.0.113.1"]}
        return [
            ctx.emit(
                Finding(
                    category=Category.SUBDOMAIN,
                    title="a.example.test",
                    target="example.test",
                )
            )
        ]


class StubScan(Module):
    name = "scan"
    label = "scan"

    def run(self, ctx):
        ctx.cancel.raise_if_cancelled()
        return [
            ctx.emit(
                Finding(
                    category=Category.PORT,
                    title="203.0.113.1:80 open",
                    severity=Severity.INFO,
                )
            )
        ]


class BoomModule(Module):
    name = "web"
    label = "web"

    def run(self, ctx):
        raise RuntimeError("kaboom")


@pytest.fixture
def stub_registry(monkeypatch):
    reg = {"recon": StubRecon(), "scan": StubScan(), "web": BoomModule()}
    monkeypatch.setattr(engine_mod, "get_registry", lambda: reg)
    return reg


# --------------------------------------------------------------------------- #
# validation / utils
# --------------------------------------------------------------------------- #


def test_normalize_target_strips_scheme_port_path():
    assert normalize_target("https://Example.COM:8443/a/b?x=1") == "example.com"
    assert normalize_target("http://10.0.0.1/") == "10.0.0.1"


@pytest.mark.parametrize(
    "value,ok",
    [
        ("example.com", True),
        ("sub.example.co.uk", True),
        ("8.8.8.8", True),
        ("::1", True),
        ("not a host", False),
        ("", False),
    ],
)
def test_validate_target(value, ok):
    assert validate_target(value)[0] is ok


def test_rate_limiter_zero_is_noop():
    rl = RateLimiter(0)
    rl.acquire()  # must not block or raise


def test_scan_for_secrets_finds_and_truncates():
    text = 'aws="AKIAIOSFODNN7EXAMPLE" token: "ghp_' + "a" * 40 + '"'
    hits = {label for label, _ in scan_for_secrets(text)}
    assert "AWS Access Key ID" in hits
    assert any("GitHub" in h for h in hits)


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #


def test_finding_dedupe_keeps_highest_severity():
    r = ScanResult(target="example.test")
    r.add(Finding(category=Category.HEADER, title="Missing CSP", severity=Severity.LOW))
    r.add(Finding(category=Category.HEADER, title="Missing CSP", severity=Severity.MEDIUM))
    assert len(r.findings) == 1
    assert r.findings[0].severity is Severity.MEDIUM


def test_scanresult_roundtrip():
    r = ScanResult(target="example.test")
    r.add(Finding(category=Category.CVE, title="CVE-1", severity=Severity.HIGH, evidence={"x": 1}))
    data = r.to_dict()
    r2 = ScanResult.from_dict(data)
    assert r2.target == "example.test"
    assert r2.findings[0].severity is Severity.HIGH
    assert r2.findings[0].evidence == {"x": 1}


def test_severity_ordering():
    assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH


# --------------------------------------------------------------------------- #
# engine
# --------------------------------------------------------------------------- #


def test_engine_runs_in_order_and_collects(stub_registry):
    cfg = Config(modules=["scan", "recon"], rate_limit=0)
    statuses = []
    eng = Engine("example.test", cfg, on_status=lambda m, s: statuses.append((m, s)))
    result = eng.run()
    # canonical order forces recon before scan despite config order
    assert result.modules_run == ["recon", "scan"]
    titles = {f.title for f in result.findings}
    assert "a.example.test" in titles
    assert any(m == "recon" and s == "done" for m, s in statuses)


def test_engine_module_error_is_isolated(stub_registry):
    cfg = Config(modules=["recon", "web", "scan"], rate_limit=0)
    errors = []
    eng = Engine(
        "example.test",
        cfg,
        on_status=lambda m, s: errors.append((m, s)) if s == "error" else None,
    )
    result = eng.run()
    # web blew up but recon+scan still ran and were recorded
    assert "recon" in result.modules_run and "scan" in result.modules_run
    assert "web" not in result.modules_run
    assert ("web", "error") in errors


def test_engine_cancel_yields_partial(stub_registry):
    cfg = Config(modules=["recon", "scan"], rate_limit=0)
    eng = Engine("example.test", cfg)
    eng.request_cancel()
    result = eng.run()
    assert result.partial is True


# --------------------------------------------------------------------------- #
# reporting + diff
# --------------------------------------------------------------------------- #


def _sample(target="example.test", extra=None):
    r = ScanResult(target=target)
    r.add(Finding(category=Category.HEADER, title="Missing CSP", severity=Severity.MEDIUM))
    if extra:
        r.add(extra)
    r.finished_at = r.started_at + 1
    return r


def test_save_and_list_runs(tmp_path: Path):
    r = _sample()
    jp = report.save_json(r, tmp_path)
    report.save_markdown(r, tmp_path)
    report.save_html(r, tmp_path)
    assert jp.exists()
    runs = report.list_runs(tmp_path)
    assert len(runs) == 1
    assert runs[0].target == "example.test"


def test_markdown_and_html_contain_findings():
    r = _sample()
    md = report.to_markdown(r)
    html = report.to_html(r)
    assert "Missing CSP" in md and "Missing CSP" in html
    assert "example.test" in html


def test_diff_added_removed():
    old = _sample()
    new = _sample(
        extra=Finding(category=Category.TLS, title="Weak TLS", severity=Severity.HIGH)
    )
    # remove the CSP finding from new to make it "resolved"
    new.findings = [f for f in new.findings if f.title != "Missing CSP"]
    d = report.diff_runs(old, new)
    assert any(f.title == "Weak TLS" for f in d.added)
    assert any(f.title == "Missing CSP" for f in d.removed)


# --------------------------------------------------------------------------- #
# config
# --------------------------------------------------------------------------- #


def test_config_overrides_skip_none():
    cfg = Config()
    out = cfg.apply_overrides(threads=None, rate_limit=99.0)
    assert out.threads == cfg.threads  # None left untouched
    assert out.rate_limit == 99.0


# --------------------------------------------------------------------------- #
# Allscan "run everything" entry point
# --------------------------------------------------------------------------- #


def test_cli_all_flag_forces_full_chain():
    from allscan.engine import MODULE_ORDER
    from allscan.main import build_parser, config_from_args

    # --all overrides a narrower --modules
    args = build_parser().parse_args(["example.test", "--all", "--modules", "web"])
    assert args.run_all is True
    assert config_from_args(args).modules == list(MODULE_ORDER)


# --------------------------------------------------------------------------- #
# expanded modules: offline logic tests
# --------------------------------------------------------------------------- #


def _make_ctx(target="example.test", state=None):
    """Build an offline ModuleContext (no network, no-op callbacks)."""
    from allscan.base import ModuleContext
    from allscan.utils import AuditLog, CancelToken, RateLimiter

    return ModuleContext(
        target=target,
        config=Config(rate_limit=0),
        rate=RateLimiter(0),
        audit=AuditLog(None),
        cancel=CancelToken(),
        state=state if state is not None else {},
        _log=lambda m, msg: None,
        _on_finding=lambda f: None,
        _module_name="test",
    )


def test_registry_order_labels_consistent():
    from allscan.base import get_registry
    from allscan.config import MODULE_LABELS
    from allscan.engine import MODULE_ORDER

    reg = set(get_registry())
    assert reg == set(MODULE_ORDER) == set(MODULE_LABELS)
    # compliance must run last so it can roll up everything
    assert MODULE_ORDER[-1] == "compliance"


def test_compliance_evaluate_flags_issues():
    from allscan.compliance import evaluate, summarize

    findings = [
        Finding(category=Category.HEADER, title="Missing content-security-policy header"),
        Finding(category=Category.TLS, title="Deprecated protocol accepted: TLSv1.0 on x",
                severity=Severity.MEDIUM),
        Finding(category=Category.EMAIL, title="Missing SPF record", severity=Severity.MEDIUM),
        Finding(category=Category.CLOUD, title="AWS S3 bucket publicly listable: http://x",
                severity=Severity.HIGH),
    ]
    rows = evaluate(findings)
    by_id = {r["id"]: r for r in rows}
    assert by_id["hdr_content-security-policy"]["status"] == "fail"
    assert by_id["tls_protocols"]["status"] == "fail"
    assert by_id["email_spf"]["status"] == "fail"
    assert by_id["exp_bucket"]["status"] == "fail"
    # a check with no corresponding finding passes
    assert by_id["dns_axfr"]["status"] == "pass"
    counts = summarize(rows)
    assert counts["fail"] >= 4


def test_compliance_module_reads_prior_findings():
    from allscan.compliance import ComplianceModule

    result = ScanResult(target="example.test")
    result.add(Finding(category=Category.EMAIL, title="Missing DMARC record",
                       severity=Severity.MEDIUM))
    ctx = _make_ctx(state={"_result": result})
    out = ComplianceModule().run(ctx)
    # summary finding + at least the DMARC fail line
    assert any(f.category == Category.COMPLIANCE and "checklist" in f.title.lower()
               for f in out)
    assert ctx.state.get("compliance")  # stashed for the report
    assert any(r["id"] == "email_dmarc" and r["status"] == "fail"
               for r in ctx.state["compliance"])


def test_cloud_extract_buckets():
    from allscan.cloud import CloudModule

    corpus = (
        "see https://my-bucket.s3.amazonaws.com/ and "
        "https://assets.s3.eu-west-1.amazonaws.com/x.png and "
        "https://acct.blob.core.windows.net/container and "
        "https://storage.googleapis.com/gcs-bucket/file"
    )
    buckets = CloudModule()._extract_buckets(corpus)
    providers = {p for p, _ in buckets}
    assert "AWS S3" in providers
    assert "Azure Blob" in providers
    assert "Google Cloud Storage" in providers


def test_waf_fingerprint_detects_cloudflare():
    from allscan.waf import WafModule

    ctx = _make_ctx()
    out = WafModule()._fingerprint(ctx, {"Server": "cloudflare", "CF-RAY": "abc123"})
    assert any("Cloudflare" in f.title for f in out)


def test_fingerprint_cms_detects_wordpress_version():
    from allscan.fingerprint import FingerprintModule

    ctx = _make_ctx()
    body = '<meta name="generator" content="WordPress 5.8.1" /> /wp-content/ wp-json'
    out = FingerprintModule()._cms(ctx, "https://example.test", "", body)
    assert any("WordPress" in f.title and "5.8.1" in f.title for f in out)
    # version-bearing CMS feeds CVE correlation
    assert any(s["product"] == "WordPress" and s["version"] == "5.8.1"
               for s in ctx.state.get("services", []))


def test_report_includes_compliance_section():
    r = ScanResult(target="example.test")
    r.add(Finding(category=Category.HEADER, title="Missing content-security-policy header"))
    r.meta = {"compliance": [
        {"id": "hdr_csp", "name": "Content-Security-Policy",
         "baseline": "OWASP Secure Headers", "status": "fail", "detail": "Header missing."},
        {"id": "tls_chain", "name": "Valid certificate chain",
         "baseline": "TLS hygiene", "status": "pass", "detail": "OK."},
    ]}
    md = report.to_markdown(r)
    html = report.to_html(r)
    assert "Compliance Checklist" in md and "Content-Security-Policy" in md
    assert "compliance checklist" in html and "FAIL" in html


# --------------------------------------------------------------------------- #
# active probing + scope enforcement (offline)
# --------------------------------------------------------------------------- #


def test_scope_guard_in_out_and_deny():
    from allscan.scope import ScopeGuard

    g = ScopeGuard("10.0.0.5", allow=["10.0.1.0/24", "app.example.com"],
                   deny=["10.0.1.9"])
    assert g.check("10.0.0.5") is True            # the target itself
    assert g.check("10.0.1.50") is True           # allow CIDR
    assert g.check("10.0.1.9") is False           # denylist wins over allow CIDR
    assert g.check("app.example.com") is True     # allow host (exact)
    assert g.check("sub.app.example.com") is True # subdomain of allowed domain
    assert g.check("8.8.8.8") is False            # out of scope
    assert g.check("evil.com") is False           # out of scope
    d = g.decide("8.8.8.8")
    assert d.allowed is False and "out of scope" in d.reason


def test_scope_guard_production_heuristic():
    from allscan.scope import ScopeGuard

    assert ScopeGuard("127.0.0.1").looks_production() is False
    assert ScopeGuard("lab.test").looks_production() is False  # lab suffix


def test_active_module_gated_off_by_default():
    from allscan.active import ActiveModule

    ctx = _make_ctx()  # Config() => active is False
    assert ctx.config.active is False
    out = ActiveModule().run(ctx)
    assert len(out) == 1
    assert out[0].category == Category.ACTIVE
    assert "disabled" in out[0].title.lower()


def test_active_finding_schema_roundtrip():
    from allscan.active import ActiveModule

    f = ActiveModule()._finding(
        "reflected-input", "http://x/?a=1 [param=a]", Severity.LOW,
        evidence={"param": "a"}, confidence="medium",
        title="Reflected input observed", description="benign marker reflected",
    )
    assert f.category == Category.ACTIVE
    assert f.location.startswith("http://x")
    assert f.target == "http://x/?a=1"
    assert f.confidence == "medium"
    assert f.note == "manual validation required"
    assert f.evidence["type"] == "reflected-input"
    # the schema fields survive JSON round-trip
    back = Finding.from_dict(f.to_dict())
    assert back.location == f.location
    assert back.confidence == "medium"
    assert back.note == "manual validation required"


def test_config_active_defaults_off_and_cli_enables():
    from allscan.main import build_parser, config_from_args

    cfg = config_from_args(build_parser().parse_args(["example.test"]))
    assert cfg.active is False
    cfg2 = config_from_args(build_parser().parse_args(
        ["example.test", "--active", "--scope-allow", "a.com,10.0.0.0/24",
         "--scope-deny", "secret.example.com"]))
    assert cfg2.active is True
    assert "a.com" in cfg2.scope_allow and "10.0.0.0/24" in cfg2.scope_allow
    assert "secret.example.com" in cfg2.scope_deny


def test_tui_allscan_runs_all_modules_and_skips_config():
    """Pressing Allscan confirms target+auth once then jumps straight to the
    live scan with every module selected, bypassing checklist + settings."""
    import asyncio

    from allscan.engine import MODULE_ORDER
    from allscan.tui import AllscanApp, ScanScreen, WelcomeScreen

    async def drive():
        # start with a deliberately narrow module set to prove Allscan overrides it
        cfg = Config(modules=["web"])
        app = AllscanApp(initial_target="example.test", config=cfg)
        async with app.run_test(size=(140, 45)) as pilot:
            await pilot.pause()
            screen = app.screen
            # without authorization, Allscan must be blocked
            screen.query_one("#auth-check").value = False
            screen.action_allscan()
            await pilot.pause()
            assert isinstance(app.screen, WelcomeScreen)
            # authorize -> Allscan jumps straight to the scan with all modules
            screen.query_one("#auth-check").value = True
            await pilot.pause()
            screen.action_allscan()
            await pilot.pause()
            assert isinstance(app.screen, ScanScreen)
            assert app.config.modules == list(MODULE_ORDER)
            assert app.target == "example.test"
            # cancel immediately so no real network scan proceeds
            app.screen.action_stop()
            await pilot.pause()

    asyncio.run(drive())
