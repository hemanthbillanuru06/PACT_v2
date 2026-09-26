"""Authentication UI component for PACT Command Center."""
import streamlit as st

from config.settings import settings
from security.lockout import AccountLockedError
from security.passwords import PasswordPolicyError
from services.auth_service import AuthService, InvalidCredentialsError, InactiveAccountError


def render_auth_page() -> None:
    """Render the official Police Assist Case Trace login portal and registration."""
    col_left, col_center, col_right = st.columns([1, 2, 1])

    with col_center:
        st.markdown(
            """
            <div class="command-header" style="text-align: center; border-left: 6px solid #1e3a8a;">
                <div style="font-size: 32px; margin-bottom: 8px;">🛡️</div>
                <h1>P.A.C.T. COMMAND SYSTEM</h1>
                <p>POLICE ASSIST CASE TRACE • LAW ENFORCEMENT INTELLIGENCE PORTAL</p>
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

        tab_login, tab_signup = st.tabs(["🔐 Officer Login", "📝 New Officer Registration"])

        with tab_login:
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

            st.caption("🔒 Law Enforcement Secure Access. Demo testing accounts are documented in `README.md`.")

        with tab_signup:
            st.subheader("Officer Registration Portal")
            st.caption("Enroll a new police officer account into the centralized state directory.")

            with st.form("signup_form", clear_on_submit=False):
                s_c1, s_c2 = st.columns(2)
                with s_c1:
                    reg_name = st.text_input("Full Officer Name", placeholder="e.g. Rajeshwar Rao")
                    reg_id = st.text_input("Officer ID (Unique)", placeholder="e.g. TS-POL-013")
                    reg_email = st.text_input("Department Email", placeholder="e.g. officer@police.gov.in")
                    reg_role = st.selectbox(
                        "Assigned Role / Jurisdiction",
                        [
                            settings.ROLE_CONSTABLE,
                            settings.ROLE_SI,
                            settings.ROLE_INVESTIGATING_OFFICER,
                            settings.ROLE_SP,
                        ],
                    )
                with s_c2:
                    reg_badge = st.text_input("Badge Number", placeholder="e.g. TS-SI-4109")
                    reg_rank = st.text_input("Official Rank / Designation", placeholder="e.g. Sub-Inspector")
                    reg_station = st.selectbox(
                        "Assigned Police Station",
                        options=[f"STN-00{i}" for i in range(1, 10)] + ["STN-010"],
                    )
                    reg_phone = st.text_input("Official Phone / CUG", placeholder="+91-9440-100013")

                reg_pwd = st.text_input(
                    "Create Password",
                    type="password",
                    placeholder="••••••••••••",
                    help="Min 12 chars with uppercase, lowercase, digit, and special symbol.",
                )
                reg_pwd_confirm = st.text_input(
                    "Confirm Password",
                    type="password",
                    placeholder="••••••••••••",
                )

                signup_btn = st.form_submit_button("REGISTER OFFICER DOCUMENT", use_container_width=True)

                if signup_btn:
                    if not reg_name or not reg_id or not reg_email or not reg_pwd:
                        st.error("Please fill in all required fields (Name, Officer ID, Email, Password).")
                    elif reg_pwd != reg_pwd_confirm:
                        st.error("Passwords do not match. Please re-enter identical passwords.")
                    else:
                        try:
                            created_officer = AuthService.register_officer(
                                full_name=reg_name,
                                officer_id=reg_id,
                                email=reg_email,
                                role=reg_role,
                                password=reg_pwd,
                                badge_number=reg_badge,
                                station_id=reg_station,
                                rank=reg_rank,
                                contact_phone=reg_phone,
                            )
                            st.success(
                                f"✅ Officer **{created_officer['full_name']}** ({created_officer['officer_id']}) "
                                f"successfully enrolled with role **{created_officer['role']}**! "
                                "You may now switch to the Officer Login tab to authenticate."
                            )
                        except (ValueError, PasswordPolicyError) as err:
                            st.error(f"Registration Error: {err}")
                        except Exception as err:
                            st.error(f"System Error during registration: {err}")
