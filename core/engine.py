import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path

from .report import Finding


@dataclass
class Context:
    target: str
    base_url: str
    root_url: str
    host: str
    domain: str
    is_ip: bool
    project_root: Path
    output_dir: Path
    raw_dir: Path
    http: object
    report: object
    config: dict
    active: bool
    depth: int
    max_pages: int
    threads: int
    max_js_files: int
    dry_run: bool
    show_secrets: bool
    data: dict = field(default_factory=dict)

    def log(self, message):
        print(f"    [{self.http.current_module}] {message}")

    def artifact(self, name, content):
        path = self.raw_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(str(content), encoding="utf-8")
        rel = str(path.relative_to(self.output_dir))
        self.report.add_artifact(self.http.current_module, rel)
        return rel

    def finding(self, wstg_id, title, severity="info", summary="", details=None, evidence=None):
        self.report.add_finding(
            wstg_id,
            Finding(title=title, severity=severity, summary=summary, details=details or {}, evidence=evidence or []),
        )

    def manual(self, wstg_id, text):
        self.report.add_manual(wstg_id, text)


def run_modules(modules, ctx):
    for mod in modules:
        mrep = ctx.report.module(mod.WSTG_ID, mod.TITLE, getattr(mod, "REFERENCE", ""))
        if getattr(mod, "ACTIVE", False) and not ctx.active:
            mrep.status = "skipped"
            mrep.manual.append("Requires --active; re-run with active checks enabled to cover this test.")
            print(f"[skip] {mod.WSTG_ID} {mod.TITLE} (requires --active)")
            continue
        ctx.http.current_module = mod.WSTG_ID
        started = time.monotonic()
        print(f"[run ] {mod.WSTG_ID} {mod.TITLE}")
        try:
            mod.run(ctx)
            mrep.status = "completed"
        except Exception as exc:
            mrep.status = "failed"
            mrep.error = f"{type(exc).__name__}: {exc}"
            print(f"[fail] {mod.WSTG_ID}: {mrep.error}")
            traceback.print_exc()
        mrep.duration_ms = int((time.monotonic() - started) * 1000)
