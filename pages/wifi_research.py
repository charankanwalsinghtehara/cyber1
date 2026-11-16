from __future__ import annotations

import streamlit as st

from agents.wifi_research_agent import WifiResearchAgent
from networking.linux_wifi import LinuxWifiProvider, WifiDiscoveryError


def render_wifi_research() -> None:
    st.title("WRAITH Research Mode")
    st.caption("Agentic Wi-Fi security assessment with a fixed, read-only tool registry.")
    st.warning(
        "Use only on networks and adapters you own or are explicitly authorized to assess. "
        "This mode performs wireless metadata discovery and local analysis; it does not crack passwords, "
        "attempt authentication, inject packets, deauthenticate clients, or create rogue access points."
    )
    authorized = st.checkbox("I have permission to assess this wireless adapter and the networks it can observe.", key="research_authorized")
    provider = LinuxWifiProvider()
    interfaces: list[str] = []
    if authorized:
        try:
            interfaces = [item["name"] for item in provider.environment()["interfaces"]]
        except (WifiDiscoveryError, OSError) as exc:
            st.error(str(exc))
    if interfaces:
        interface = st.selectbox("Wireless interface", interfaces, key="research_interface")
        if st.button("Run autonomous read-only assessment", type="primary"):
            try:
                result = WifiResearchAgent(provider=provider).run(interface, authorized=True)
            except (WifiDiscoveryError, PermissionError, ValueError) as exc:
                st.error(str(exc))
            else:
                st.session_state["wraith_research_result"] = result
    elif authorized:
        st.info("No supported wireless adapter was detected.")
    else:
        st.info("Confirm authorization to enumerate local wireless adapters.")

    result = st.session_state.get("wraith_research_result")
    if result:
        st.subheader("Agent execution trace")
        st.dataframe(result.get("steps", []), use_container_width=True, hide_index=True)
        st.metric("Risk indicator", f"{result.get('risk_indicator', 0)}/100")
        st.write(result.get("summary", ""))
        if result.get("networks"):
            st.subheader("Observed networks")
            st.dataframe(result["networks"], use_container_width=True, hide_index=True)
        if result.get("findings"):
            st.subheader("Evidence-backed findings")
            st.dataframe(result["findings"], use_container_width=True, hide_index=True)
        st.subheader("Assessment limitations")
        for limitation in result.get("limitations", []):
            st.markdown(f"- {limitation}")
        st.download_button(
            "Download research JSON",
            data=__import__("json").dumps(result, indent=2),
            file_name=f"wraith-{result['assessment_id']}.json",
            mime="application/json",
        )

    st.divider()
    st.subheader("Router hardening review")
    st.caption("Answer from your router's admin settings. The agent does not log in to or modify the router.")
    with st.form("router_hardening_review"):
        cols = st.columns(2)
        modern = cols[0].checkbox("WPA3 or WPA2-AES enabled")
        wps = cols[1].checkbox("WPS disabled")
        firmware = cols[0].checkbox("Firmware is current")
        admin = cols[1].checkbox("Default admin password changed")
        remote = cols[0].checkbox("Remote administration restricted")
        guest = cols[1].checkbox("Guest network isolated")
        submitted = st.form_submit_button("Analyze router hardening")
    if submitted:
        controls = WifiResearchAgent.analyze_router_hardening({
            "modern_encryption": modern, "wps_disabled": wps,
            "firmware_current": firmware, "admin_password_changed": admin,
            "remote_admin_restricted": remote, "guest_isolated": guest,
        })
        st.dataframe(controls, use_container_width=True, hide_index=True)
