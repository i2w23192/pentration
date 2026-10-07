"""Engagement / project platform (local, file-based).

Phase-5 workflow layer that sits around the scan engine without changing it:

* **Project / engagement** — name, client, scope (allow/deny), rules-of-engagement
  text, a testing window, and stored **authorization evidence** (file + SHA-256 +
  who/when). Scope and window feed scanning so active work stays in bounds and
  in time.
* **Findings ledger** — findings ingested from runs are deduplicated by a stable
  fingerprint and carry a **status workflow** (open → confirmed / false-positive /
  fixed / accepted / regression), with first/last-seen and per-finding history.
* **Retest management** — compares a new run against the ledger baseline and links
  each prior finding to fixed / not-fixed / regression (before/after).
* **Evidence chain-of-custody** — arbitrary evidence files are copied into the
  project store with a SHA-256, size, timestamp and the tester's identity, and
  every custody action is appended to an activity log.

Everything is JSON on disk under ``projects_dir/<name>/``; no server, no network.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from allscan.models import Finding, ScanResult, Severity

# finding status workflow
STATUSES = ("open", "confirmed", "false-positive", "fixed", "accepted", "regression")


def tester_identity() -> str:
    """Who is acting, for attribution. ALLSCAN_TESTER overrides the OS user."""
    who = os.environ.get("ALLSCAN_TESTER")
    if who:
        return who
    try:
        import getpass
        return getpass.getuser()
    except Exception:  # pragma: no cover
        return "unknown"


def _now() -> float:
    return time.time()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def fingerprint(finding) -> str:
    """Stable id for dedup/correlation across runs: hash of (category,target,title)."""
    if isinstance(finding, dict):
        key = (finding.get("category", ""), finding.get("target", ""),
               finding.get("title", ""))
    else:
        key = finding.dedupe_key()
    return hashlib.sha256("|".join(str(k) for k in key).encode()).hexdigest()[:16]


@dataclass
class Project:
    name: str
    path: Path
    data: dict

    # --- lifecycle --------------------------------------------------------
    @classmethod
    def new(cls, name: str, path: Path, client: str = "") -> "Project":
        data = {
            "name": name,
            "client": client,
            "created": _now(),
            "created_by": tester_identity(),
            "scope": {"allow": [], "deny": []},
            "roe": "",
            "window": {"start": None, "end": None},
            "authorization": [],
            "evidence": [],
            "runs": [],
            "findings": {},
            "retests": [],
            "activity": [],
        }
        p = cls(name=name, path=path, data=data)
        p.activity("create", f"project '{name}' created" + (f" for {client}" if client else ""))
        return p

    def save(self) -> None:
        self.path.mkdir(parents=True, exist_ok=True)
        (self.path / "project.json").write_text(
            json.dumps(self.data, indent=2, default=str))

    # --- activity / attribution ------------------------------------------
    def activity(self, action: str, detail: str = "", actor: Optional[str] = None) -> None:
        self.data["activity"].append({
            "ts": _now(), "actor": actor or tester_identity(),
            "action": action, "detail": detail})

    # --- engagement config ------------------------------------------------
    def set_scope(self, allow=None, deny=None) -> None:
        if allow is not None:
            self.data["scope"]["allow"] = list(allow)
        if deny is not None:
            self.data["scope"]["deny"] = list(deny)
        self.activity("set_scope", f"allow={self.data['scope']['allow']} "
                                   f"deny={self.data['scope']['deny']}")

    def set_roe(self, text: str) -> None:
        self.data["roe"] = text
        self.activity("set_roe", f"{len(text)} chars")

    def set_window(self, start: Optional[str], end: Optional[str]) -> None:
        self.data["window"] = {"start": start, "end": end}
        self.activity("set_window", f"{start} .. {end}")

    def within_window(self, when: Optional[float] = None) -> bool:
        w = self.data.get("window") or {}
        start, end = _parse(w.get("start")), _parse(w.get("end"))
        t = when if when is not None else _now()
        if start and t < start:
            return False
        if end and t > end:
            return False
        return True

    # --- authorization evidence ------------------------------------------
    def add_authorization(self, file_path: str, note: str = "") -> dict:
        src = Path(file_path)
        if not src.is_file():
            raise FileNotFoundError(file_path)
        dest_dir = self.path / "authorization"
        dest_dir.mkdir(parents=True, exist_ok=True)
        digest = sha256_file(src)
        dest = dest_dir / f"{digest[:12]}_{src.name}"
        shutil.copy2(src, dest)
        rec = {"file": src.name, "stored_path": str(dest), "sha256": digest,
               "size": src.stat().st_size, "added": _now(),
               "added_by": tester_identity(), "note": note}
        self.data["authorization"].append(rec)
        self.activity("add_authorization", f"{src.name} sha256={digest[:12]}…")
        return rec

    @property
    def has_authorization(self) -> bool:
        return bool(self.data.get("authorization"))

    # --- evidence chain-of-custody ---------------------------------------
    def add_evidence(self, file_path: str, note: str = "") -> dict:
        src = Path(file_path)
        if not src.is_file():
            raise FileNotFoundError(file_path)
        dest_dir = self.path / "evidence"
        dest_dir.mkdir(parents=True, exist_ok=True)
        digest = sha256_file(src)
        eid = f"EV-{len(self.data['evidence']) + 1:04d}"
        dest = dest_dir / f"{eid}_{digest[:12]}_{src.name}"
        shutil.copy2(src, dest)
        rec = {"id": eid, "name": src.name, "stored_path": str(dest),
               "sha256": digest, "size": src.stat().st_size,
               "added": _now(), "added_by": tester_identity(), "note": note,
               "custody": [{"ts": _now(), "actor": tester_identity(),
                            "action": "acquired", "sha256": digest}]}
        self.data["evidence"].append(rec)
        self.activity("add_evidence", f"{eid} {src.name} sha256={digest[:12]}…")
        return rec

    def verify_evidence(self) -> list[dict]:
        """Re-hash stored evidence and report integrity (chain-of-custody check)."""
        out = []
        for rec in self.data.get("evidence", []):
            stored = Path(rec["stored_path"])
            ok = stored.is_file() and sha256_file(stored) == rec["sha256"]
            out.append({"id": rec["id"], "name": rec["name"], "intact": ok})
            rec.setdefault("custody", []).append(
                {"ts": _now(), "actor": tester_identity(),
                 "action": "verify", "intact": ok})
        self.activity("verify_evidence", f"{sum(1 for o in out if o['intact'])}/{len(out)} intact")
        return out

    # --- runs + findings ledger ------------------------------------------
    def ingest_run(self, result: ScanResult, run_path: Optional[str] = None) -> dict:
        run_id = f"RUN-{len(self.data['runs']) + 1:04d}"
        self.data["runs"].append({
            "id": run_id, "target": result.target, "started": result.started_at,
            "finding_count": len(result.findings), "path": run_path or ""})
        ledger = self.data["findings"]
        new, updated = 0, 0
        for f in result.findings:
            fp = fingerprint(f)
            rec = ledger.get(fp)
            if rec is None:
                ledger[fp] = {
                    "fingerprint": fp, "title": f.title, "category": f.category,
                    "severity": f.severity.value, "target": f.target,
                    "location": f.location, "status": "open",
                    "first_seen": run_id, "last_seen": run_id, "runs": [run_id],
                    "history": [{"ts": _now(), "actor": tester_identity(),
                                 "action": "discovered", "run": run_id}]}
                new += 1
            else:
                rec["last_seen"] = run_id
                if run_id not in rec["runs"]:
                    rec["runs"].append(run_id)
                # keep the highest severity seen
                if Severity.from_str(f.severity.value).rank > Severity.from_str(rec["severity"]).rank:
                    rec["severity"] = f.severity.value
                # a finding that was marked fixed but reappears => regression
                if rec["status"] == "fixed":
                    rec["status"] = "regression"
                    rec["history"].append({"ts": _now(), "actor": tester_identity(),
                                           "action": "regression", "run": run_id})
                updated += 1
        self.activity("ingest_run", f"{run_id} {result.target}: {new} new, {updated} updated")
        return {"run_id": run_id, "new": new, "updated": updated}

    def set_finding_status(self, fp: str, status: str, note: str = "",
                           actor: Optional[str] = None) -> dict:
        if status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        rec = self.data["findings"].get(fp)
        if rec is None:
            raise KeyError(fp)
        old = rec["status"]
        rec["status"] = status
        rec.setdefault("history", []).append(
            {"ts": _now(), "actor": actor or tester_identity(),
             "action": "status", "from": old, "to": status, "note": note})
        self.activity("set_status", f"{fp} {old}->{status}", actor=actor)
        return rec

    # --- retest -----------------------------------------------------------
    def retest(self, result: ScanResult, run_path: Optional[str] = None) -> dict:
        """Compare a fresh run against the current ledger, linking prior
        findings to fixed / not-fixed, and flagging regressions / new."""
        baseline = {fp: rec for fp, rec in self.data["findings"].items()}
        prior_open = {fp for fp, rec in baseline.items()
                      if rec["status"] not in ("fixed", "false-positive")}
        # ingest updates last_seen + regression handling
        info = self.ingest_run(result, run_path)
        present = {fingerprint(f) for f in result.findings}

        fixed, not_fixed, regressions, new = [], [], [], []
        for fp in prior_open:
            if fp in present:
                not_fixed.append(fp)
            else:
                # no longer observed -> mark fixed
                rec = self.data["findings"][fp]
                if rec["status"] != "fixed":
                    rec["status"] = "fixed"
                    rec.setdefault("history", []).append(
                        {"ts": _now(), "actor": tester_identity(),
                         "action": "retest-fixed", "run": info["run_id"]})
                fixed.append(fp)
        for fp in present:
            rec = self.data["findings"].get(fp, {})
            if rec.get("status") == "regression":
                regressions.append(fp)
            elif fp not in baseline:
                new.append(fp)

        report = {"run_id": info["run_id"], "target": result.target, "when": _now(),
                  "fixed": fixed, "not_fixed": not_fixed,
                  "regressions": regressions, "new": new,
                  "counts": {"fixed": len(fixed), "not_fixed": len(not_fixed),
                             "regressions": len(regressions), "new": len(new)}}
        self.data["retests"].append(report)
        self.activity("retest", f"{info['run_id']}: {report['counts']}")
        return report

    # --- queries ----------------------------------------------------------
    def findings_by_status(self) -> dict[str, list]:
        out: dict[str, list] = {}
        for rec in self.data["findings"].values():
            out.setdefault(rec["status"], []).append(rec)
        return out


class ProjectStore:
    def __init__(self, base_dir: str):
        self.base = Path(base_dir)

    def _dir(self, name: str) -> Path:
        safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in name)
        return self.base / safe

    def exists(self, name: str) -> bool:
        return (self._dir(name) / "project.json").is_file()

    def create(self, name: str, client: str = "") -> Project:
        if self.exists(name):
            raise FileExistsError(name)
        p = Project.new(name, self._dir(name), client)
        p.save()
        return p

    def load(self, name: str) -> Project:
        path = self._dir(name)
        data = json.loads((path / "project.json").read_text())
        return Project(name=data.get("name", name), path=path, data=data)

    def list(self) -> list[dict]:
        out = []
        if not self.base.exists():
            return out
        for d in sorted(self.base.iterdir()):
            pj = d / "project.json"
            if pj.is_file():
                try:
                    data = json.loads(pj.read_text())
                    out.append({"name": data.get("name", d.name),
                                "client": data.get("client", ""),
                                "runs": len(data.get("runs", [])),
                                "findings": len(data.get("findings", {})),
                                "authorized": bool(data.get("authorization"))})
                except Exception:
                    continue
        return out


def _parse(value) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    import datetime
    v = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.datetime.fromisoformat(v)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.timestamp()
    except ValueError:
        for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M"):
            try:
                return datetime.datetime.strptime(str(value)[:16], fmt).timestamp()
            except ValueError:
                continue
    return None
