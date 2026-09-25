"""Sidebar navigation and officer identity component."""
from typing import Dict, Any
import streamlit as st

from config.settings import settings
from services.auth_service import AuthService


def render_sidebar(current_user: Dict[str, Any]) -> str:
    """Render the officer identity panel and navigation in the sidebar.

    Returns the selected navigation target.
    """
    with st.sidebar:
        # Command Center Insignia
        st.markdown(
            """
            <div style="text-align: center; padding: 12px 0 16px 0; border-bottom: 1px solid #1e293b;">
                <div style="font-size: 28px;">👮‍♂️</div>
                <div style="font-weight: 800; font-size: 16px; color: #f8fafc; letter-spacing: 1px;">PACT COMMAND</div>
                <div style="font-size: 11px; color: #64748b; letter-spacing: 0.5px;">STATE POLICE INTELLIGENCE</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

        # Officer Badge Card
        role = current_user.get("role", "CONSTABLE")
        full_name = current_user.get("full_name", "Officer")
        officer_id = current_user.get("officer_id", "N/A")
        badge = current_user.get("badge_number", "N/A")
        station_id = current_user.get("station_id", "N/A")
        rank = current_user.get("rank", role)

        st.markdown(
            f"""
            <div class="officer-badge-card">
                <div class="officer-name">{full_name}</div>
                <div class="officer-id">{officer_id} • {badge}</div>
                <div style="margin-bottom: 8px;">
                    <span class="badge-role badge-{role}">{role}</span>
                </div>
                <div style="font-size: 11px; color: #94a3b8;">
                    <strong>Rank:</strong> {rank}<br>
                    <strong>Assigned Station:</strong> {station_id}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("<hr style='border-color: #1e293b; margin: 12px 0;'>", unsafe_allow_html=True)
        st.caption("TACTICAL NAVIGATION")

        # Navigation Options
        nav_options = [
            ("🏢 Command Overview", "overview"),
            ("📡 Station Registry (10)", "stations"),
            ("🛡️ Personnel Directory", "officers"),
        ]

        # Audit Logs visible in menu for ADMIN and SP
        if role in [settings.ROLE_ADMIN, settings.ROLE_SP]:
            nav_options.append(("📜 Security Audit Trail", "audit_logs"))

        # Lockout control visible for ADMIN
        if role == settings.ROLE_ADMIN:
            nav_options.append(("⚙️ Security Telemetry & Lockouts", "security_admin"))

        current_nav = st.session_state.get("active_nav", "overview")

        # Find matching label
        labels = [opt[0] for opt in nav_options]
        target_keys = [opt[1] for opt in nav_options]

        default_idx = 0
        if current_nav in target_keys:
            default_idx = target_keys.index(current_nav)

        selected_label = st.radio(
            "Navigation",
            options=labels,
            index=default_idx,
            label_visibility="collapsed",
        )

        selected_key = target_keys[labels.index(selected_label)]
        st.session_state["active_nav"] = selected_key

        st.markdown("<hr style='border-color: #1e293b; margin: 24px 0 12px 0;'>", unsafe_allow_html=True)

        # Logout Button
        if st.button("🚪 DISCONNECT / LOGOUT", use_container_width=True):
            AuthService.logout(user=current_user, ip_address="127.0.0.1")
            st.session_state.clear()
            st.rerun()

        st.caption("SECURE SESSION ID")
        st.code(f"SESS-{officer_id[-4:]}-ACTIVE", language="text")

    return selected_key
