from __future__ import annotations

"""Agentic, read-only Wi-Fi security research workflow.

The planner can select only registered, non-invasive assessment steps. It never
performs authentication attempts, credential guessing, deauthentication, packet
injection, rogue-AP creation, or arbitrary shell execution.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable
import uuid

from agents.wifi_security_analysis_agent import WifiSecurityAnalysisAgent
from networking.linux_wifi import LinuxWifiProvider


@dataclass(frozen=True)
class ResearchStep:
    name: str
    purpose: str
    tool: str


class WifiResearchAgent:
    """Plan, observe, assess, and critique an authorized Wi-Fi metadata audit."""

    def __init__(self, provider: LinuxWifiProvider | None = None) -> None:
        self.provider = provider or LinuxWifiProvider()
        self.analyzer = WifiSecurityAnalysisAgent()
        self.tool_registry: dict[str, Callable[..., Any]] = {
            "discover_wireless_metadata": self.provider.discover,
        }

    def build_plan(self, interface: str) -> list[ResearchStep]:
        if not isinstance(interface, str) or not interface.strip():
            raise ValueError("A wireless interface is required.")
        # Fixed allowlisted tools: the model/planner cannot invent commands.
        return [
            ResearchStep("interface_discovery", "Read nearby beacon and network metadata", "discover_wireless_metadata"),
            ResearchStep("security_posture", "Classify advertised Wi-Fi security and WPS metadata", "local_security_analyzer"),
            ResearchStep("risk_review", "Prioritize evidence-backed findings and identify blind spots", "local_risk_critic"),
        ]

    def run(self, interface: str, authorized: bool) -> dict[str, Any]:
        assessment_id = str(uuid.uuid4())
        if authorized is not True:
            return {"assessment_id": assessment_id, "status": "blocked", "summary": "Explicit authorization is required.", "steps": [], "networks": [], "findings": []}

        plan = self.build_plan(interface)
        execution_log: list[dict[str, str]] = []
        networks: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []

        # Step 1: observe. No shell or command string is accepted from an LLM.
        step = plan[0]
        discovered = self.tool_registry[step.tool](interface)
        networks = [item.to_dict() for item in discovered]
        execution_log.append({"step": step.name, "status": "complete", "evidence": f"{len(networks)} network metadata record(s)"})

        # Step 2: deterministic analysis of observable beacon metadata.
        for network in networks:
            findings.extend(self.analyzer.analyze(network))
        execution_log.append({"step": plan[1].name, "status": "complete", "evidence": f"{len(findings)} finding(s) generated"})

        # Step 3: critic distinguishes observable facts from unverified assumptions.
        findings = self._critic(findings)
        execution_log.append({"step": plan[2].name, "status": "complete", "evidence": "Evidence and confidence labels reviewed"})

        counts = {level: sum(1 for f in findings if f.get("severity") == level) for level in ("Critical", "High", "Medium", "Low", "Informational")}
        score = min(100, counts["Critical"] * 35 + counts["High"] * 20 + counts["Medium"] * 10 + counts["Low"] * 4)
        summary = (
            f"Agentic read-only assessment completed: {len(networks)} network(s), "
            f"{len(findings)} finding(s), risk indicator {score}/100. "
            "This evaluates advertised metadata only; it does not verify passphrases, router settings, or exploitability."
        )
        return {
            "assessment_id": assessment_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "completed",
            "mode": "authorized_read_only_research",
            "interface": interface,
            "summary": summary,
            "risk_indicator": score,
            "severity_counts": counts,
            "plan": [{"step": s.name, "purpose": s.purpose, "tool": s.tool} for s in plan],
            "steps": execution_log,
            "networks": networks,
            "findings": findings,
            "limitations": [
                "Beacon metadata cannot reveal the Wi-Fi passphrase.",
                "Beacon metadata cannot prove the router's full configuration or firmware state.",
                "No authentication attempts, packet injection, password guessing, or client disruption were performed.",
            ],
        }

    @staticmethod
    def _critic(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        reviewed = []
        for original in findings:
            finding = dict(original)
            evidence = str(finding.get("evidence", ""))
            finding["evidence_boundary"] = (
                "Observed in wireless discovery metadata; not an authenticated configuration test."
                if evidence else "No direct evidence recorded; manual validation required."
            )
            if finding.get("title") == "WPA2 configuration review":
                finding["severity"] = "Informational"
                finding["confidence"] = "High"
            reviewed.append(finding)
        return reviewed

    @staticmethod
    def analyze_router_hardening(config: dict[str, Any]) -> list[dict[str, str]]:
        """Review admin-supplied router settings; does not connect to the router."""
        checks = [
            ("WPA3 or WPA2-AES", config.get("modern_encryption") is True, "Use WPA3-Personal or WPA2-AES; disable WEP/TKIP/legacy WPA."),
            ("WPS disabled", config.get("wps_disabled") is True, "Disable WPS in the router administration interface."),
            ("Router firmware current", config.get("firmware_current") is True, "Install the vendor-supported firmware update."),
            ("Admin password changed", config.get("admin_password_changed") is True, "Replace default router administrator credentials with a unique password."),
            ("Remote administration restricted", config.get("remote_admin_restricted") is True, "Disable WAN-side administration or restrict it to a trusted management path."),
            ("Guest network isolated", config.get("guest_isolated") is True, "Enable guest/client isolation where appropriate."),
        ]
        return [{"control": name, "status": "Pass" if passed else "Review", "recommendation": advice} for name, passed, advice in checks]
