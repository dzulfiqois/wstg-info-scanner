import json
from dataclasses import dataclass, field

from . import TOOL_NAME, VERSION
from .util import now_iso

SEVERITIES = ["critical", "high", "medium", "low", "info"]


@dataclass
class Finding:
    title: str
    severity: str = "info"
    summary: str = ""
    details: dict = field(default_factory=dict)
    evidence: list = field(default_factory=list)


@dataclass
class ModuleReport:
    wstg_id: str
    title: str
    reference: str
    status: str = "pending"
    error: str = ""
    duration_ms: int = 0
    findings: list = field(default_factory=list)
    manual: list = field(default_factory=list)
    artifacts: list = field(default_factory=list)


def _format(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def _render_details(details, max_rows=100):
    lines = []
    for key, value in (details or {}).items():
        if key == "mermaid":
            lines.append("")
            lines.append("```mermaid")
            lines.append(str(value))
            lines.append("```")
        elif key == "table" and isinstance(value, list) and value and isinstance(value[0], dict):
            columns = list(value[0].keys())
            lines.append("")
            lines.append("| " + " | ".join(columns) + " |")
            lines.append("|" + "|".join("---" for _ in columns) + "|")
            for row in value[:max_rows]:
                cells = [str(row.get(col, "")).replace("|", "\\|").replace("\n", " ") for col in columns]
                lines.append("| " + " | ".join(cells) + " |")
            if len(value) > max_rows:
                lines.append("")
                lines.append(f"_showing {max_rows} of {len(value)} rows_")
        elif isinstance(value, list):
            if not value:
                continue
            lines.append(f"- **{key}:**")
            for item in value[:max_rows]:
                lines.append(f"  - {_format(item)}")
            if len(value) > max_rows:
                lines.append(f"  - _...and {len(value) - max_rows} more_")
        else:
            lines.append(f"- **{key}:** {_format(value)}")
    return "\n".join(lines).strip()


class Report:
    def __init__(self, target, output_dir, active, started):
        self.target = target
        self.output_dir = output_dir
        self.active = active
        self.started = started
        self.modules = {}
        self.artifacts = set()

    def module(self, wstg_id, title, reference):
        if wstg_id not in self.modules:
            self.modules[wstg_id] = ModuleReport(wstg_id, title, reference)
        return self.modules[wstg_id]

    def add_finding(self, wstg_id, finding):
        self.module(wstg_id, "", "").findings.append(finding)

    def add_manual(self, wstg_id, text):
        self.module(wstg_id, "", "").manual.append(text)

    def add_artifact(self, wstg_id, relpath):
        self.artifacts.add(relpath)
        self.module(wstg_id, "", "").artifacts.append(relpath)

    def to_dict(self, duration_s=None):
        total = {sev: 0 for sev in SEVERITIES}
        modules = []
        for mr in self.modules.values():
            findings = []
            for finding in mr.findings:
                findings.append(
                    {
                        "title": finding.title,
                        "severity": finding.severity,
                        "summary": finding.summary,
                        "details": finding.details,
                        "evidence": finding.evidence,
                    }
                )
                total[finding.severity] = total.get(finding.severity, 0) + 1
            modules.append(
                {
                    "wstg_id": mr.wstg_id,
                    "title": mr.title,
                    "reference": mr.reference,
                    "status": mr.status,
                    "error": mr.error,
                    "duration_ms": mr.duration_ms,
                    "artifacts": mr.artifacts,
                    "manual_followup": mr.manual,
                    "findings": findings,
                }
            )
        return {
            "meta": {
                "tool": TOOL_NAME,
                "version": VERSION,
                "target": self.target,
                "active": self.active,
                "started": self.started,
                "finished": now_iso(),
                "duration_seconds": duration_s,
            },
            "summary": {
                "findings_total": sum(total.values()),
                "by_severity": total,
                "artifacts": sorted(self.artifacts),
            },
            "modules": modules,
        }

    def write_json(self, path, duration_s=None):
        path.write_text(json.dumps(self.to_dict(duration_s), indent=2, ensure_ascii=False), encoding="utf-8")

    def write_markdown(self, path, duration_s=None):
        data = self.to_dict(duration_s)
        meta = data["meta"]
        lines = []
        lines.append(f'# WSTG-INFO Reconnaissance Report - <span style="color:red">{meta["target"]}</span>')
        lines.append("")
        lines.append("> Automated reconnaissance output. Every entry is a candidate lead: validate manually before reporting it as a finding.")
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|---|---|")
        lines.append(f'| Target | <span style="color:red">{meta["target"]}</span> |')
        lines.append(f"| Started (UTC) | {meta['started']} |")
        lines.append(f"| Duration | {meta.get('duration_seconds')}s |")
        lines.append(f"| Active checks | {'yes' if meta['active'] else 'no'} |")
        lines.append(f"| Findings | {data['summary']['findings_total']} |")
        lines.append("")
        by_sev = data["summary"]["by_severity"]
        lines.append("## Severity Summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|---|---|")
        for sev in SEVERITIES:
            lines.append(f"| {sev} | {by_sev.get(sev, 0)} |")
        lines.append("")
        lines.append("## Coverage")
        lines.append("")
        lines.append("| WSTG ID | Test | Status | Findings |")
        lines.append("|---|---|---|---|")
        for mod in data["modules"]:
            counts = {}
            for finding in mod["findings"]:
                counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
            counts_text = ", ".join(f"{v} {k}" for k, v in counts.items()) or "-"
            lines.append(f"| {mod['wstg_id']} | [{mod['title']}]({mod['reference']}) | {mod['status']} | {counts_text} |")
        lines.append("")
        lines.append("## Findings by Module")
        for mod in data["modules"]:
            lines.append("")
            lines.append(f"### {mod['wstg_id']} - {mod['title']}")
            lines.append("")
            if mod["status"] != "completed":
                suffix = f" - {mod['error']}" if mod["error"] else ""
                lines.append(f"Status: **{mod['status']}**{suffix}")
                lines.append("")
            if not mod["findings"]:
                lines.append("No automated findings.")
            for index, finding in enumerate(mod["findings"], 1):
                lines.append("")
                lines.append(f"#### {mod['wstg_id']}-{index} [{finding['severity'].upper()}] {finding['title']}")
                lines.append("")
                if finding["summary"]:
                    lines.append(finding["summary"])
                    lines.append("")
                details = _render_details(finding.get("details"))
                if details:
                    lines.append(details)
                    lines.append("")
                if finding.get("evidence"):
                    lines.append("Evidence: " + ", ".join(f"`{item}`" for item in finding["evidence"]))
            if mod.get("manual_followup"):
                lines.append("")
                lines.append("**Manual follow-up**")
                lines.append("")
                for item in mod["manual_followup"]:
                    lines.append(f"- [ ] {item}")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("Generated by wstg-info. WSTG reference: https://owasp.org/www-project-web-security-testing-guide/")
        path.write_text("\n".join(lines), encoding="utf-8")
