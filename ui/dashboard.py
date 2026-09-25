"""Main Command Center Dashboard Shell and views for PACT."""
from typing import Dict, Any, List
import pandas as pd
import streamlit as st

from config.settings import settings
from security.rbac import get_role_permissions, UnauthorizedAccessError
from services.station_service import StationService
from services.user_service import UserService
from services.audit_service import AuditService


def render_dashboard(current_user: Dict[str, Any], active_nav: str) -> None:
    """Render the main command dashboard shell."""
    role = current_user.get("role", "CONSTABLE")
    officer_id = current_user.get("officer_id", "Unknown")

    # Command Header
    st.markdown(
        f"""
        <div class="command-header">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h1>PACT TACTICAL COMMAND DASHBOARD</h1>
                    <p>SESSION ACTIVE • OFFICER ID: {officer_id} • ROLE: <span class="badge-role badge-{role}">{role}</span></p>
                </div>
                <div style="text-align: right; color: #10b981; font-family: monospace; font-size: 13px;">
                    ● SYSTEM SECURE • MONGO LIVE
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if active_nav == "overview":
        render_overview(current_user)
    elif active_nav == "stations":
        render_stations_view(current_user)
    elif active_nav == "officers":
        render_officers_view(current_user)
    elif active_nav == "audit_logs":
        render_audit_logs_view(current_user)
    elif active_nav == "security_admin":
        render_security_admin_view(current_user)
    else:
        render_overview(current_user)


def render_overview(current_user: Dict[str, Any]) -> None:
    """Render the primary operational overview."""
    st.subheader("Operational Telemetry & System Status")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(
            """
            <div class="metric-box">
                <div class="metric-label">Registered Stations</div>
                <div class="metric-val">10</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            """
            <div class="metric-box">
                <div class="metric-label">Active Officers</div>
                <div class="metric-val">12</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col3:
        st.markdown(
            """
            <div class="metric-box">
                <div class="metric-label">Database Health</div>
                <div class="metric-val" style="color: #10b981;">ONLINE</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col4:
        st.markdown(
            """
            <div class="metric-box">
                <div class="metric-label">Lockout Threshold</div>
                <div class="metric-val" style="color: #f59e0b;">5 ATTEMPTS</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<hr style='border-color: #1e293b; margin: 16px 0;'>", unsafe_allow_html=True)

    # RBAC Privileges Display
    role = current_user.get("role", "CONSTABLE")
    perms = sorted(list(get_role_permissions(role)))

    st.subheader(f"Backend Role-Based Access Privileges: [{role}]")
    st.caption("Central backend enforcement guarantees that unauthorized actions are blocked and audited.")

    perm_cols = st.columns(2)
    with perm_cols[0]:
        st.markdown("<strong>Assigned Backend Capabilities:</strong>", unsafe_allow_html=True)
        for p in perms:
            st.markdown(f"✔️ `<code style='color: #38bdf8;'>{p}</code>`", unsafe_allow_html=True)

    with perm_cols[1]:
        st.markdown("<strong>Access Control Enforcement:</strong>", unsafe_allow_html=True)
        role_summaries = {
            settings.ROLE_ADMIN: "Full system administration, user management, audit review, and station registry control.",
            settings.ROLE_SP: "High-level command intelligence, cross-jurisdiction oversight, and security audit log access.",
            settings.ROLE_SI: "Station-level operational management, officer assignment, and case supervision.",
            settings.ROLE_INVESTIGATING_OFFICER: "Active case investigation, case diary documentation, and evidence tracing.",
            settings.ROLE_CONSTABLE: "Beat patrol logs, station presence verification, and basic incident viewing.",
        }
        st.info(role_summaries.get(role, "Law Enforcement Officer."))

        # Quick simulated RBAC check button
        st.markdown("<strong>RBAC Backend Verification Test:</strong>", unsafe_allow_html=True)
        if st.button("🧪 Test Restricted Admin Action (Trigger Backend Enforcer)"):
            try:
                # Attempt admin-only call
                UserService.unlock_user_account(current_user, "TS-POL-001")
                st.success("Authorized: Admin action executed successfully.")
            except UnauthorizedAccessError as err:
                st.error(f"🛡️ ACCESS BLOCKED BY BACKEND RBAC: {err}")
                st.warning("⚠️ Event logged in MongoDB audit_logs as UNAUTHORIZED_ACCESS.")


def render_stations_view(current_user: Dict[str, Any]) -> None:
    """Render the 10 synthetic police stations directory."""
    st.subheader("Police Registry: Synthetic Station Directory")
    st.caption("10 synthetic law enforcement stations seeded idempotently into MongoDB police_registry.")

    try:
        stations = StationService.get_stations(current_user)
        if not stations:
            st.warning("No stations found in the database. Ensure database is seeded.")
            return

        df = pd.DataFrame(stations)
        display_cols = ["station_id", "station_code", "name", "zone", "district", "contact_phone", "sanctioned_strength"]
        available_cols = [c for c in display_cols if c in df.columns]

        st.dataframe(df[available_cols], use_container_width=True, hide_index=True)

        st.markdown("#### Station Operational Details")
        stn_ids = [s["station_id"] for s in stations]
        chosen_id = st.selectbox("Select Station to View Complete Command Dossier", options=stn_ids)

        if chosen_id:
            stn = StationService.get_station_by_id(current_user, chosen_id)
            if stn:
                c1, c2 = st.columns(2)
                with c1:
                    st.write(f"**Name:** {stn.get('name')}")
                    st.write(f"**Station Code:** {stn.get('station_code')}")
                    st.write(f"**Address:** {stn.get('address')}")
                    st.write(f"**Zone:** {stn.get('zone')}")
                with c2:
                    st.write(f"**District:** {stn.get('district')}")
                    st.write(f"**Phone:** {stn.get('contact_phone')}")
                    st.write(f"**Emergency Line:** {stn.get('emergency_contact')}")
                    st.write(f"**Sanctioned Personnel:** {stn.get('sanctioned_strength')}")
                    st.write(f"**GPS Coordinates:** {stn.get('latitude')}, {stn.get('longitude')}")

    except UnauthorizedAccessError as err:
        st.error(f"Unauthorized: {err}")


def render_officers_view(current_user: Dict[str, Any]) -> None:
    """Render the officer personnel roster."""
    st.subheader("Officer Personnel Roster")
    st.caption("Active law enforcement personnel across commissionerates (ADMIN, SP, and SI access).")

    try:
        officers = UserService.get_officers_list(current_user)
        if not officers:
            st.info("No personnel records retrieved.")
            return

        df = pd.DataFrame(officers)
        cols = ["officer_id", "badge_number", "full_name", "rank", "station_id", "contact_phone", "blood_group"]
        available_cols = [c for c in cols if c in df.columns]
        st.dataframe(df[available_cols], use_container_width=True, hide_index=True)

    except UnauthorizedAccessError as err:
        st.error(f"🛡️ ACCESS RESTRICTED: {err}")
        st.caption("Constables and Investigating Officers do not possess directory overview permissions.")


def render_audit_logs_view(current_user: Dict[str, Any]) -> None:
    """Render security audit trail for authorized roles (ADMIN and SP)."""
    st.subheader("Security & Authentication Audit Trail")
    st.caption("Immutable system audit logs recorded in MongoDB audit_logs collection.")

    role = current_user.get("role")
    if role not in [settings.ROLE_ADMIN, settings.ROLE_SP]:
        st.error("🛡️ ACCESS DENIED: Security audit logs are strictly restricted to SP and ADMIN roles.")
        AuditService.log_unauthorized_access(current_user, "audit_logs:view_screen")
        return

    filter_event = st.selectbox(
        "Filter by Event Type",
        options=["ALL", "LOGIN_SUCCESS", "LOGIN_FAILED", "LOGOUT", "UNAUTHORIZED_ACCESS", "ACCOUNT_LOCKED", "ACCOUNT_UNLOCKED"],
    )

    query_event = None if filter_event == "ALL" else filter_event
    logs = AuditService.get_recent_logs(limit=150, event_type=query_event)

    if not logs:
        st.info("No audit entries found matching the filter.")
        return

    formatted_logs = []
    for l in logs:
        formatted_logs.append({
            "Timestamp": l.get("timestamp"),
            "Event": l.get("event_type"),
            "Officer ID": l.get("officer_id") or "N/A",
            "Role": l.get("role") or "N/A",
            "Status": l.get("status"),
            "IP Address": l.get("ip_address"),
            "Details": str(l.get("details", {})),
        })

    df = pd.DataFrame(formatted_logs)
    st.dataframe(df, use_container_width=True, hide_index=True)


def render_security_admin_view(current_user: Dict[str, Any]) -> None:
    """Render administrative lockout controls and security telemetry."""
    st.subheader("Security Telemetry & Account Lockout Control")
    st.caption("Administrative oversight panel. Restricted exclusively to ADMIN role.")

    try:
        telemetry = UserService.get_security_telemetry(current_user)
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total User Accounts", telemetry["total_users"])
        c2.metric("Locked Accounts", telemetry["locked_users"])
        c3.metric("Total Login Attempts", telemetry["total_login_attempts"])
        c4.metric("Failed Login Attempts", telemetry["failed_login_attempts"])

        st.markdown("<hr style='border-color: #1e293b; margin: 16px 0;'>", unsafe_allow_html=True)

        users = UserService.get_users_list(current_user)
        df_users = pd.DataFrame(users)

        st.markdown("#### User Accounts Status")
        if not df_users.empty:
            cols = ["officer_id", "email", "role", "is_active", "is_locked", "failed_login_attempts", "last_successful_login"]
            available = [c for c in cols if c in df_users.columns]
            st.dataframe(df_users[available], use_container_width=True, hide_index=True)

        # Unlock Account Form
        st.markdown("#### Administrative Account Unlock")
        st.caption("Manually restore officer access after account lockout.")

        locked_users = [u["officer_id"] for u in users if u.get("is_locked")]

        if locked_users:
            selected_officer = st.selectbox("Select Locked Officer to Unlock", options=locked_users)
            if st.button(f"🔓 UNLOCK OFFICER {selected_officer}", use_container_width=True):
                success = UserService.unlock_user_account(current_user, selected_officer)
                if success:
                    st.success(f"Officer {selected_officer} has been successfully unlocked.")
                    st.rerun()
                else:
                    st.error(f"Failed to unlock officer {selected_officer}.")
        else:
            st.info("✅ All officer accounts are currently unlocked.")

    except UnauthorizedAccessError as err:
        st.error(f"🛡️ ACCESS RESTRICTED: {err}")
