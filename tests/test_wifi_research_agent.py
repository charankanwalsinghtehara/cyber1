from dataclasses import dataclass

from agents.wifi_research_agent import WifiResearchAgent


@dataclass
class FakeNetwork:
    ssid: str
    bssid: str
    channel: int
    frequency_mhz: int
    signal_percent: int
    security: str
    wps_exposed: bool = False

    def to_dict(self):
        return self.__dict__.copy()


class FakeProvider:
    def discover(self, interface):
        assert interface == "wlan0"
        return [FakeNetwork("Lab", "AA:BB:CC:DD:EE:FF", 6, 2437, 80, "WPA2")]


def test_research_agent_runs_fixed_read_only_plan():
    result = WifiResearchAgent(provider=FakeProvider()).run("wlan0", authorized=True)
    assert result["status"] == "completed"
    assert [step["step"] for step in result["steps"]] == [
        "interface_discovery", "security_posture", "risk_review"
    ]
    assert result["networks"][0]["ssid"] == "Lab"
    assert "evidence_boundary" in result["findings"][0]
    assert "does not verify" in result["summary"]


def test_research_agent_blocks_without_authorization():
    result = WifiResearchAgent(provider=FakeProvider()).run("wlan0", authorized=False)
    assert result["status"] == "blocked"
    assert result["networks"] == []


def test_router_hardening_review_reports_missing_controls():
    results = WifiResearchAgent.analyze_router_hardening({})
    assert len(results) == 6
    assert all(item["status"] == "Review" for item in results)
