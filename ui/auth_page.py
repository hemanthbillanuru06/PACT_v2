"""Authentication UI component for PACT Command Center."""
import streamlit as st

from config.settings import settings
from security.lockout import AccountLockedError
from services.auth_service import AuthService, InvalidCredentialsError, InactiveAccountError


def render_auth_page() -> None:
    """Render the official Police Assist Case Trace login portal."""
    col_left, col_center, col_right = st.columns([1, 2, 1])

    with col_center:
        st.markdown(
            """
            <div class="command-header" style="text-align: center; border-left: 6px solid #1e3a8a;">
                <div style="font-size: 32px; margin-bottom: 8px;">🛡️</div>
                <h1>P.A.C.T. COMMAND SYSTEM</h1>
                <p>POLICE ASSIST CASE TRACE • PHASE 1 INTELLIGENCE ACCESS</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown(
            """
            <div class="security-notice">
                ⚠️ <strong>OFFICIAL LAW ENFORCEMENT ACCESS ONLY</strong><br>
                Unauthorized access or tampering is strictly prohibited under the Information Technology Act.
                All authentication events and IP addresses are recorded in immutable audit logs.
            </div>
            """,
            unsafe_allow_html=True,
        )

        with st.form("login_form", clear_on_submit=False):
            st.subheader("Officer Authentication")
            identifier = st.text_input(
                "Officer ID or Official Email",
                placeholder="e.g. TS-POL-001 or ts-pol-001@police.gov.in",
                help="Enter your unique Officer Badge ID or authorized department email address.",
            )
            password = st.text_input(
                "Command Password",
                type="password",
                placeholder="••••••••••••",
                help=f"Minimum {settings.PASSWORD_MIN_LENGTH} characters with upper, lower, numeric, and special character.",
            )

            submit_btn = st.form_submit_button("AUTHENTICATE & ENTER PORTAL", use_container_width=True)

            if submit_btn:
                if not identifier.strip():
                    st.error("Officer ID or Email is required.")
                elif not password:
                    st.error("Command Password is required.")
                else:
                    try:
                        user_session = AuthService.authenticate(
                            identifier=identifier.strip(),
                            password=password,
                            ip_address="127.0.0.1",
                        )
                        st.session_state["authenticated_user"] = user_session
                        st.session_state["active_nav"] = "overview"
                        st.success(f"Authentication verified for {user_session['full_name']} ({user_session['role']}).")
                        st.rerun()

                    except AccountLockedError as err:
                        st.error(f"🚨 ACCESS DENIED: {err}")
                    except InvalidCredentialsError as err:
                        st.error(f"❌ {err}")
                    except InactiveAccountError as err:
                        st.error(f"⛔ {err}")

        # Synthetic Credentials Reference Guide for Testing
        with st.expander("📋 Synthetic Personnel Directory (Phase 1 Testing Reference)"):
            st.markdown(
                """
                | Officer ID | Role | Name | Station | Standard Password |
                | :--- | :--- | :--- | :--- | :--- |
                | `TS-POL-001` | **SP** | Vikramaditya Varma, IPS | Cyberabad Central | `Pact@Officer2026!` |
                | `TS-POL-002` | **SP** | Dr. Ananya Deshmukh, IPS | Punjagutta Command | `Pact@Officer2026!` |
                | `TS-POL-003` | **SI** | Rajeshwar Rao | Banjara Hills PS | `Pact@Officer2026!` |
                | `TS-POL-004` | **SI** | Pradeep K. Reddy | Madhapur IT PS | `Pact@Officer2026!` |
                | `TS-POL-005` | **SI** | Sunita G. Naidu | Cyber Crime Div | `Pact@Officer2026!` |
                | `TS-POL-006` | **IO** | K. Vamsi Krishna | Cyber Crime Div | `Pact@Officer2026!` |
                | `TS-POL-007` | **IO** | Sneha Patel | Banjara Hills PS | `Pact@Officer2026!` |
                | `TS-POL-008` | **IO** | T. Arvind Chary | Madhapur IT PS | `Pact@Officer2026!` |
                | `TS-POL-009` | **IO** | Meera Varma | Jubilee Hills PS | `Pact@Officer2026!` |
                | `TS-POL-010` | **CONSTABLE** | D. Suresh Kumar | Cyberabad Central | `Pact@Officer2026!` |
                | `TS-POL-011` | **CONSTABLE** | B. Ramesh Goud | Cyber Crime Div | `Pact@Officer2026!` |
                | `TS-POL-012` | **ADMIN** | System Administrator | State IT Directorate | `Pact@Admin2026!` |
                """
            )
            st.info("ℹ️ Account lockout test: 5 consecutive failed attempts on an officer ID will lock the account.")
