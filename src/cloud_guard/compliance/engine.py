from pathlib import Path

import yaml

from cloud_guard.scanners.base import ScanResult


class ComplianceFramework:
    def __init__(self, name: str, version: str, controls: dict[str, dict]):
        self.name = name
        self.version = version
        self.controls = controls

    @classmethod
    def from_yaml(cls, path: Path) -> "ComplianceFramework":
        data = yaml.safe_load(path.read_text())
        return cls(
            name=data["name"],
            version=data["version"],
            controls={c["id"]: c for c in data["controls"]},
        )

    def evaluate(self, result: ScanResult) -> dict:
        matched = set()
        for finding in result.findings:
            if finding.compliance_control and finding.compliance_control in self.controls:
                matched.add(finding.compliance_control)

        total = len(self.controls)
        passed = total - len(matched)
        score = (passed / total * 100) if total > 0 else 100.0

        return {
            "framework": self.name,
            "version": self.version,
            "total_controls": total,
            "passed": passed,
            "failed": len(matched),
            "score": round(score, 1),
            "failed_controls": [
                {
                    "id": cid,
                    "title": self.controls[cid]["title"],
                    "severity": self.controls[cid].get("severity", "medium"),
                }
                for cid in matched
            ],
        }


class ComplianceEngine:
    def __init__(self, policies_dir: Path | None = None):
        self.policies_dir = policies_dir or Path(__file__).parent.parent.parent.parent / "policies"
        self.frameworks: dict[str, ComplianceFramework] = {}
        self._load_frameworks()

    def _load_frameworks(self) -> None:
        if not self.policies_dir.exists():
            return
        for path in self.policies_dir.glob("*.yml"):
            fw = ComplianceFramework.from_yaml(path)
            self.frameworks[fw.name] = fw

    def evaluate(self, result: ScanResult, framework_name: str | None = None) -> list[dict]:
        if framework_name and framework_name in self.frameworks:
            return [self.frameworks[framework_name].evaluate(result)]
        return [fw.evaluate(result) for fw in self.frameworks.values()]
