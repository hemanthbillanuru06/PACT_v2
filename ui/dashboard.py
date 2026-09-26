"""Main Command Center Dashboard Shell and views for PACT Phase 1 and Phase 2."""
import os
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import pydeck as pdk
import streamlit as st

from config.settings import settings
from database.connection import get_db
from security.rbac import get_role_permissions, UnauthorizedAccessError
from services.case_service import CaseService, CaseSecurityValidator
from services.entity_service import EntityService
from services.evidence_service import EvidenceService
from services.semantic_search import SemanticSearchEngine
from services.report_service import ReportService
from services.notification_service import NotificationService
from services.station_service import StationService
from services.user_service import UserService
from services.audit_service import AuditService
from services.gemini_service import GeminiService, GeminiAnalysisResult, GeminiKeyMissingError


def render_dashboard(current_user: Dict[str, Any], active_nav: str) -> None:
    """Render the main command dashboard shell based on navigation selection."""
    role = current_user.get("role", "CONSTABLE")
    officer_id = current_user.get("officer_id", "Unknown")

    # Command Header
    st.markdown(
        f"""
        <div class="command-header">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h1>PACT TACTICAL COMMAND DASHBOARD</h1>
                    <p>PHASE 2 INVESTIGATION-MANAGEMENT LAYER • OFFICER: {officer_id} • ROLE: <span class="badge-role badge-{role}">{role}</span></p>
                </div>
                <div style="text-align: right; color: #10b981; font-family: monospace; font-size: 13px;">
                    ● SYSTEM SECURE • MONGO LIVE • INTEL ACTIVE
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if active_nav == "overview":
        render_overview(current_user)
    elif active_nav == "cases":
        render_cases_view(current_user)
    elif active_nav == "firs":
        render_firs_view(current_user)
    elif active_nav == "evidence":
        render_evidence_view(current_user)
    elif active_nav == "ai_assistant":
        render_ai_assistant_view(current_user)
    elif active_nav == "semantic_search":
        render_semantic_search_view(current_user)
    elif active_nav == "analytics":
        render_analytics_view(current_user)
    elif active_nav == "notifications":
        render_notifications_view(current_user)
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


# =============================================================================
# View 1: Command Overview
# =============================================================================
def render_overview(current_user: Dict[str, Any]) -> None:
    """Primary operational overview with Phase 2 metrics."""
    st.subheader("Operational Telemetry & System Status")

    metrics = ReportService.get_analytics_metrics(current_user)
    total_cases = metrics.get("total_cases", 0)

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(
            f"""
            <div class="metric-box">
                <div class="metric-label">Active Case Dossiers</div>
                <div class="metric-val">{total_cases}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            """
            <div class="metric-box">
                <div class="metric-label">Registered Stations</div>
                <div class="metric-val">10</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col3:
        st.markdown(
            """
            <div class="metric-box">
                <div class="metric-label">Active Officers</div>
                <div class="metric-val">12</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col4:
        st.markdown(
            """
            <div class="metric-box">
                <div class="metric-label">Database Health</div>
                <div class="metric-val" style="color: #10b981;">ONLINE (pact_db)</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Showcase Case Callout
    st.markdown(
        """
        <div style="background-color: #111a2c; border-left: 5px solid #38bdf8; border-top: 1px solid #1e293b; border-right: 1px solid #1e293b; border-bottom: 1px solid #1e293b; padding: 14px 18px; border-radius: 4px; margin: 16px 0;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <strong style="color: #38bdf8; font-size: 14px;">🎯 MANDATORY SHOWCASE CASE ACTIVE</strong><br>
                    <span style="color: #cbd5e1; font-size: 13px;">
                        <strong>Case ID:</strong> <code>PACT-CASE-2026-0042</code> • <strong>FIR:</strong> <code>TS/NORTH/2026/0042</code> • 
                        <strong>Crime:</strong> Vehicle Theft • <strong>Priority:</strong> HIGH • <strong>Station:</strong> North Station • <strong>Lead IO:</strong> TS-POL-003
                    </span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if st.button("🔍 Inspect Showcase Case Dossier (PACT-CASE-2026-0042)", key="btn_showcase_inspect"):
        st.session_state["selected_case_id"] = "PACT-CASE-2026-0042"
        st.session_state["active_nav"] = "cases"
        st.rerun()

    st.markdown("<hr style='border-color: #1e293b; margin: 16px 0;'>", unsafe_allow_html=True)

    # RBAC Privileges Display
    role = current_user.get("role", "CONSTABLE")
    perms = sorted(list(get_role_permissions(role)))

    st.subheader(f"Backend Role-Based Access Privileges: [{role}]")
    st.caption("Service-level RBAC guarantees that Officer A cannot view or alter Officer B's cases.")

    perm_cols = st.columns(2)
    with perm_cols[0]:
        st.markdown("<strong>Assigned Backend Capabilities:</strong>", unsafe_allow_html=True)
        for p in perms:
            st.markdown(f"✔️ `<code style='color: #38bdf8;'>{p}</code>`", unsafe_allow_html=True)

    with perm_cols[1]:
        st.markdown("<strong>Jurisdictional Enforcement:</strong>", unsafe_allow_html=True)
        role_summaries = {
            settings.ROLE_ADMIN: "Department-wide administration. Unrestricted access to all cases, evidence, and stations.",
            settings.ROLE_SP: "Superintendent executive oversight across all stations. Full audit and case supervision clearance.",
            settings.ROLE_SI: "Station-level command. Complete control over assigned station cases, assigning IOs, and review.",
            settings.ROLE_INVESTIGATING_OFFICER: "Lead investigator clearance strictly for assigned cases. Cross-case access blocked.",
            settings.ROLE_CONSTABLE: "Patrol assistance clearance. Restricted to explicitly assigned support tasks.",
        }
        st.info(role_summaries.get(role, "Law Enforcement Officer."))


# =============================================================================
# View 2: Case Dossiers (Complete Case Management)
# =============================================================================
def render_cases_view(current_user: Dict[str, Any]) -> None:
    """Render interactive Case Dossiers management."""
    st.subheader("📁 Case Investigation Dossiers")
    st.caption("Central law enforcement case files with service-level access control.")

    # Filter controls
    c1, c2, c3, c4 = st.columns([2, 1, 1, 1])
    with c1:
        search_query = st.text_input("Search Case Title or Modus Operandi", placeholder="e.g. Fortuner, CAN-bus, Phishing...")
    with c2:
        status_sel = st.selectbox("Status", ["ALL", "UNDER INVESTIGATION", "OPEN", "CHARGESHEETED", "CLOSED", "COLD_CASE"])
    with c3:
        prio_sel = st.selectbox("Priority", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    with c4:
        if st.button("⭐ Jump to Showcase", use_container_width=True):
            st.session_state["selected_case_id"] = "PACT-CASE-2026-0042"
            st.rerun()

    # Query cases via service (service-level RBAC enforced)
    cases = CaseService.get_cases(
        current_user=current_user,
        status_filter=status_sel,
        priority_filter=prio_sel,
        limit=200,
    )

    if search_query.strip():
        q_lower = search_query.strip().lower()
        cases = [c for c in cases if q_lower in c.get("title", "").lower() or q_lower in c.get("modus_operandi", "").lower() or q_lower in c.get("case_id", "").lower()]

    if not cases:
        st.warning("No cases found matching your operational clearance or filters.")
        return

    # Select case to view
    case_ids = [c["case_id"] for c in cases]
    default_case = st.session_state.get("selected_case_id")
    default_idx = 0
    if default_case in case_ids:
        default_idx = case_ids.index(default_case)

    selected_case_id = st.selectbox("Select Case Dossier to Open", options=case_ids, index=default_idx)
    st.session_state["selected_case_id"] = selected_case_id

    # Fetch complete case dossier with strict RBAC enforcement
    try:
        case_doc = CaseService.get_case_by_id(current_user, selected_case_id)
        if not case_doc:
            st.error("Case not found.")
            return

        render_single_case_dossier(current_user, case_doc)

    except UnauthorizedAccessError as err:
        st.error(f"🛡️ ACCESS RESTRICTED BY SERVICE-LEVEL RBAC: {err}")
        st.caption("Unauthorized case inspection blocked and recorded in audit trail.")


def render_single_case_dossier(current_user: Dict[str, Any], case: Dict[str, Any]) -> None:
    """Render comprehensive dossier for an authorized case."""
    case_id = case["case_id"]
    prio = case.get("priority", "MEDIUM")
    status = case.get("status", "OPEN")

    st.markdown(
        f"""
        <div style="background-color: #111a2c; border: 1px solid #1e2e4a; border-left: 6px solid #2563eb; border-radius: 6px; padding: 18px; margin: 12px 0;">
            <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                <div>
                    <h3 style="margin: 0; color: #f8fafc;">{case.get('title')}</h3>
                    <p style="margin: 4px 0 0 0; color: #94a3b8; font-size: 13px;">
                        <strong>Case ID:</strong> <code style="color: #38bdf8;">{case_id}</code> • 
                        <strong>FIR:</strong> <code>{case.get('fir_number')}</code> • 
                        <strong>Station:</strong> {case.get('station_id')} • 
                        <strong>Lead IO:</strong> <code style="color: #38bdf8;">{case.get('io_officer_id')}</code>
                    </p>
                </div>
                <div>
                    <span class="badge-role" style="background-color: #1e3a8a; color: #bfdbfe; margin-right: 6px;">{prio} PRIORITY</span>
                    <span class="badge-role" style="background-color: #14532d; color: #bbf7d0;">{status}</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Dossier Tabs
    tab_overview, tab_people, tab_property, tab_evidence, tab_custody, tab_timeline, tab_notes, tab_ai, tab_export = st.tabs([
        "📋 Overview & MO",
        "👥 People",
        "📦 Property",
        "📁 Evidence Vault",
        "⛓️ Chain of Custody",
        "⏱️ Timeline",
        "📓 Case Diary",
        "🤖 Gemini AI Assistant",
        "📄 Export Dossier",
    ])

    # Tab 1: Overview & MO
    with tab_overview:
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("#### Executive Summary")
            st.write(case.get("summary", "No summary recorded."))
            st.write(f"**Crime Type:** {case.get('crime_type')}")
            st.write(f"**Location:** {case.get('location', 'N/A')}")
        with c2:
            st.markdown("#### Modus Operandi (MO)")
            st.info(case.get("modus_operandi", "No Modus Operandi cataloged."))
            st.write(f"**Assigned Officers:** {', '.join(case.get('assigned_officers', []))}")

        # Status Update Action
        can_write = CaseSecurityValidator.can_access_case(current_user, case, require_write=True)
        if can_write:
            st.markdown("#### Update Status & Priority")
            u_cols = st.columns([2, 2, 1])
            with u_cols[0]:
                new_status = st.selectbox("Update Status", ["UNDER INVESTIGATION", "CHARGESHEETED", "CLOSED", "COLD_CASE", "OPEN"], index=0, key=f"sel_st_{case_id}")
            with u_cols[1]:
                new_prio = st.selectbox("Update Priority", ["LOW", "MEDIUM", "HIGH", "CRITICAL"], index=2, key=f"sel_pr_{case_id}")
            with u_cols[2]:
                st.write("")
                st.write("")
                if st.button("Save Changes", key=f"btn_save_case_{case_id}"):
                    CaseService.update_case(current_user, case_id, {"status": new_status, "priority": new_prio})
                    st.success("Case updated.")
                    st.rerun()

    # Tab 2: People (Complainants, Victims, Suspects, Witnesses)
    with tab_people:
        st.markdown("#### Suspects Cataloged")
        suspects = EntityService.get_suspects(current_user, case_id)
        if suspects:
            st.dataframe(pd.DataFrame(suspects)[["name", "alias", "status", "physical_description", "prior_convictions"]], use_container_width=True, hide_index=True)
        else:
            st.info("No suspects recorded.")

        st.markdown("#### Complainants & Victims")
        col_c, col_v = st.columns(2)
        with col_c:
            st.caption("COMPLAINANTS")
            comps = EntityService.get_complainants(current_user, case_id)
            for c in comps:
                st.write(f"👤 **{c.get('name')}** • Phone: {c.get('contact_phone')}")
                st.caption(f"Statement: {c.get('statement_summary')}")
        with col_v:
            st.caption("VICTIMS")
            victims = EntityService.get_victims(current_user, case_id)
            for v in victims:
                st.write(f"👤 **{v.get('name')}** (Age: {v.get('age')}, {v.get('gender')})")
                st.caption(f"Injuries: {v.get('injuries_reported')}")

        st.markdown("#### Witnesses")
        witnesses = EntityService.get_witnesses(current_user, case_id)
        if witnesses:
            st.dataframe(pd.DataFrame(witnesses)[["name", "contact_phone", "credibility_notes", "statement_summary"]], use_container_width=True, hide_index=True)
        else:
            st.caption("No witness depositions on file.")

    # Tab 3: Property
    with tab_property:
        st.markdown("#### Recovered & Stolen Property Items")
        items = EntityService.get_property_items(current_user, case_id)
        if items:
            st.dataframe(pd.DataFrame(items)[["item_type", "description", "estimated_value_inr", "serial_or_reg_number", "recovery_status"]], use_container_width=True, hide_index=True)
        else:
            st.info("No property items logged.")

    # Tab 4: Evidence Vault
    with tab_evidence:
        st.markdown("#### Digital & Physical Evidence Vault")
        st.caption("Secure evidence files verified with SHA-256 cryptographic hashes and path traversal security.")

        evidence_list = EvidenceService.get_case_evidence(current_user, case_id)
        if evidence_list:
            for ev in evidence_list:
                ev_id = ev.get("evidence_id")
                with st.expander(f"📦 {ev.get('name')} ({ev.get('evidence_type')}) - ID: {ev_id}"):
                    c1, c2 = st.columns([3, 1])
                    with c1:
                        st.write(f"**Description:** {ev.get('description')}")
                        st.write(f"**Current Custodian:** `{ev.get('current_custodian_id')}`")
                        st.write(f"**SHA-256 Hash:** `{ev.get('sha256_hash')}`")
                        st.write(f"**MIME Type:** `{ev.get('mime_type')}` • **Size:** {ev.get('file_size_bytes')} bytes")
                    with c2:
                        try:
                            file_bytes, orig_name, mime = EvidenceService.download_evidence(current_user, ev_id)
                            st.download_button(
                                label="⬇️ Download File",
                                data=file_bytes,
                                file_name=orig_name,
                                mime=mime,
                                key=f"dl_{ev_id}",
                                use_container_width=True,
                            )
                        except Exception as err:
                            st.warning(f"Download unavailable: {err}")
        else:
            st.info("No evidence registered.")

        # Upload New Evidence Form
        can_write = CaseSecurityValidator.can_access_case(current_user, case, require_write=True)
        if can_write:
            with st.expander("➕ Register New Evidence Item (Path-Traversal Protected)"):
                with st.form(f"form_ev_{case_id}", clear_on_submit=True):
                    ev_name = st.text_input("Item Name", placeholder="e.g. CCTV Recording, Recovered Phone")
                    ev_type = st.selectbox("Evidence Type", ["DIGITAL_MEDIA", "DOCUMENT", "PHYSICAL", "FORENSIC", "WEAPON"])
                    ev_desc = st.text_area("Item Description")
                    uploaded_file = st.file_uploader("Upload Evidence File", type=["mp4", "jpg", "png", "pdf", "txt", "doc"])
                    submit_ev = st.form_submit_button("Register & Ingest Evidence")

                    if submit_ev:
                        if not ev_name or not uploaded_file:
                            st.error("Item name and file are required.")
                        else:
                            content = uploaded_file.read()
                            EvidenceService.register_evidence(
                                current_user=current_user,
                                case_id=case_id,
                                content=content,
                                original_filename=uploaded_file.name,
                                name=ev_name,
                                evidence_type=ev_type,
                                description=ev_desc,
                            )
                            st.success("Evidence successfully registered with SHA-256 integrity hash.")
                            st.rerun()

    # Tab 5: Chain of Custody
    with tab_custody:
        st.markdown("#### Auditable Chain of Custody")
        st.caption("Immutable record of physical and digital custody transfers.")

        if evidence_list:
            ev_options = [e["evidence_id"] for e in evidence_list]
            sel_ev_id = st.selectbox("Select Evidence Item to View Custody Trail", options=ev_options, key=f"cust_sel_{case_id}")

            custody_trail = EvidenceService.get_custody_history(current_user, sel_ev_id)
            if custody_trail:
                st.dataframe(pd.DataFrame(custody_trail)[["transfer_id", "from_officer_id", "to_officer_id", "transfer_reason", "authorized_by", "timestamp"]], use_container_width=True, hide_index=True)

            # Transfer Custody Action
            can_write = CaseSecurityValidator.can_access_case(current_user, case, require_write=True)
            if can_write:
                with st.expander("🔄 Transfer Custody to Another Officer"):
                    with st.form(f"form_transfer_{sel_ev_id}"):
                        to_off = st.selectbox("Transfer To Officer", options=[f"TS-POL-00{i}" for i in range(1, 10)] + ["TS-POL-010", "TS-POL-011"])
                        reason = st.selectbox("Transfer Reason", [
                            "FORENSIC_LAB_EXAMINATION",
                            "COURT_HEARING_PRESENTATION",
                            "SECURE_VAULT_DEPOSIT",
                            "BALLISTICS_INSPECTION",
                            "OFFICER_REASSIGNMENT"
                        ])
                        notes = st.text_input("Transfer Notes / Seal Number")
                        submit_trf = st.form_submit_button("Execute Custody Transfer")

                        if submit_trf:
                            EvidenceService.transfer_custody(current_user, sel_ev_id, to_off, reason, notes)
                            st.success(f"Custody of {sel_ev_id} transferred to {to_off}.")
                            st.rerun()
        else:
            st.info("No evidence registered to transfer.")

    # Tab 6: Timeline
    with tab_timeline:
        st.markdown("#### Chronological Investigation Timeline")
        timeline = CaseService.get_case_timeline(current_user, case_id)
        if timeline:
            for t in timeline:
                st.markdown(f"🗓️ **{t.get('timestamp')}** • `{t.get('event_type')}` — **{t.get('title')}**")
                st.caption(f"{t.get('description')} (Recorded by: {t.get('recorded_by')})")
                st.markdown("<hr style='margin: 4px 0 8px 0; border-color: #1e293b;'>", unsafe_allow_html=True)
        else:
            st.info("No timeline milestones.")

        can_write = CaseSecurityValidator.can_access_case(current_user, case, require_write=True)
        if can_write:
            with st.expander("➕ Add Investigation Milestone"):
                with st.form(f"form_tl_{case_id}"):
                    t_title = st.text_input("Milestone Title")
                    t_type = st.selectbox("Event Type", ["INCIDENT", "ARREST", "SEARCH", "INTERROGATION", "EVIDENCE_SEIZED", "LEAD", "CHARGESHEET"])
                    t_desc = st.text_area("Milestone Description")
                    if st.form_submit_button("Record Milestone"):
                        CaseService.add_timeline_event(current_user, case_id, {"title": t_title, "event_type": t_type, "description": t_desc})
                        st.success("Milestone added.")
                        st.rerun()

    # Tab 7: Case Diary Notes
    with tab_notes:
        st.markdown("#### Case Diary & Tactical Notes")
        notes = CaseService.get_case_notes(current_user, case_id)
        if notes:
            for n in notes:
                badge_conf = "🔒 CONFIDENTIAL" if n.get("is_confidential") else "📝 GENERAL"
                st.markdown(f"**{n.get('author_name')}** ({n.get('author_id')}) • `{badge_conf}` • {n.get('created_at')}")
                st.write(n.get("content"))
                st.markdown("<hr style='margin: 4px 0 8px 0; border-color: #1e293b;'>", unsafe_allow_html=True)
        else:
            st.info("No case diary notes recorded.")

        can_write = CaseSecurityValidator.can_access_case(current_user, case, require_write=True)
        if can_write:
            with st.expander("✍️ Add Case Diary Entry"):
                with st.form(f"form_note_{case_id}"):
                    n_type = st.selectbox("Note Type", ["DIARY_ENTRY", "TACTICAL_NOTE", "SUPERVISORY_DIRECTIVE", "FORENSIC_LEAD"])
                    n_content = st.text_area("Observation / Entry")
                    n_conf = st.checkbox("Mark as Confidential")
                    if st.form_submit_button("Submit Diary Entry"):
                        CaseService.add_case_note(current_user, case_id, {"note_type": n_type, "content": n_content, "is_confidential": n_conf})
                        st.success("Entry saved.")
                        st.rerun()

    # Tab 8: Gemini AI Assistant
    with tab_ai:
        st.markdown("#### 🤖 Google Gemini Investigative Assistant")
        st.caption("AI-powered investigative intelligence grounded strictly on verified case facts, timeline, evidence, and entity records.")

        api_key_configured = bool(getattr(settings, "GEMINI_API_KEY", "") or os.getenv("GEMINI_API_KEY", ""))
        if api_key_configured:
            st.success(f"● Gemini Engine Online • Model: `{settings.GEMINI_MODEL}` • Grounding Enforced")
        else:
            st.warning("⚠️ Gemini Engine Offline: `GEMINI_API_KEY` is not set in `.env`. Case dossiers, evidence tracking, and semantic search remain 100% operational.")

        # Analysis Selection & Invocation
        st.markdown("##### 1. Structured Case Analysis")
        col_type, col_action = st.columns([3, 2])
        with col_type:
            analysis_labels = {
                "CASE_SUMMARY": "📋 Executive Case Summary (Senior Leadership)",
                "INVESTIGATION_BRIEF": "🔍 Tactical Detective Briefing (MO & Leads)",
                "EVIDENCE_SUMMARY": "🔬 Evidence & Forensics Integrity Assessment",
                "TIMELINE_ANALYSIS": "⏱️ Timeline Reconstruction & Chronological Gap Analysis",
                "INVESTIGATIVE_QUESTIONS": "❓ Strategic Interrogation & Inquiry Question Generator",
                "CASE_COMPARISON": "⚖️ Side-by-Side Case Comparison",
            }
            selected_analysis = st.selectbox(
                "Select Intelligence Product",
                options=list(analysis_labels.keys()),
                format_func=lambda x: analysis_labels.get(x, x),
                key=f"sel_ai_type_{case_id}",
            )

        comp_case_id = None
        if selected_analysis == "CASE_COMPARISON":
            other_cases = CaseService.get_cases(current_user, limit=50)
            other_ids = [c["case_id"] for c in other_cases if c["case_id"] != case_id]
            if other_ids:
                comp_case_id = st.selectbox("Select Case to Compare Against", options=other_ids, key=f"sel_comp_{case_id}")
            else:
                st.info("No other accessible cases available for comparison.")

        with col_action:
            st.write("")
            st.write("")
            run_btn = st.button("⚡ Generate Analysis", key=f"btn_run_ai_{case_id}", use_container_width=True)

        if run_btn:
            with st.spinner("Analyzing case records with Gemini AI..."):
                res = GeminiService.analyze_case(
                    current_user=current_user,
                    case_id=case_id,
                    analysis_type=selected_analysis,
                    comparison_case_id=comp_case_id,
                )
                st.session_state[f"last_ai_result_{case_id}"] = res.to_dict()

        # Display last result if available
        last_res = st.session_state.get(f"last_ai_result_{case_id}")
        if last_res:
            if last_res.get("status") == "SUCCESS":
                st.markdown("---")
                st.markdown(f"**Analysis Report: `{last_res.get('analysis_type')}`** (Generated in {last_res.get('duration_seconds')}s)")
                st.markdown(last_res.get("output", ""))
            elif last_res.get("status") == "KEY_MISSING":
                st.info(last_res.get("error_message"))
            else:
                st.error(last_res.get("error_message", "AI processing encountered an error."))

        st.markdown("---")
        # Interactive Officer Q&A
        st.markdown("##### 2. Officer Case Q&A Assistant")
        st.caption("Ask questions strictly bounded to verified facts in this case dossier.")
        qa_col1, qa_col2 = st.columns([4, 1])
        with qa_col1:
            officer_q = st.text_input("Enter your investigative question", placeholder="e.g. What forensic tools were used by the perpetrators? What is the suspect's alibi?", key=f"qa_input_{case_id}")
        with qa_col2:
            st.write("")
            st.write("")
            qa_btn = st.button("🔍 Ask Assistant", key=f"btn_qa_ask_{case_id}", use_container_width=True)

        if qa_btn and officer_q.strip():
            with st.spinner("Consulting case dossier records..."):
                qa_res = GeminiService.analyze_case(
                    current_user=current_user,
                    case_id=case_id,
                    analysis_type="OFFICER_QA",
                    officer_query=officer_q.strip(),
                )
                st.session_state[f"last_qa_result_{case_id}"] = qa_res.to_dict()

        last_qa = st.session_state.get(f"last_qa_result_{case_id}")
        if last_qa:
            if last_qa.get("status") == "SUCCESS":
                st.markdown(f"**Response:**\n\n{last_qa.get('output')}")
            elif last_qa.get("status") == "KEY_MISSING":
                st.info(last_qa.get("error_message"))
            else:
                st.error(last_qa.get("error_message"))

        # Historical AI Analysis Ledger
        with st.expander("📜 Historical AI Analysis Ledger for this Case"):
            hist = GeminiService.get_case_ai_history(current_user, case_id)
            if hist:
                for h in hist:
                    st.markdown(f"🗓️ **{h.get('timestamp')}** • `{h.get('analysis_type')}` • Officer: `{h.get('officer_id')}` • Duration: `{h.get('duration_seconds')}s`")
                    st.caption(h.get("output", "")[:250] + "..." if len(h.get("output", "")) > 250 else h.get("output", ""))
                    st.markdown("<hr style='margin: 4px 0 8px 0; border-color: #1e293b;'>", unsafe_allow_html=True)
            else:
                st.caption("No prior AI analyses recorded for this case.")

    # Tab 9: Export Dossier
    with tab_export:
        st.markdown("#### Official Law Enforcement Dossier Generation")
        st.caption("Generate a court-ready PDF dossier containing all case intelligence, suspects, evidence, and chain of custody.")

        col_pdf, col_spacer = st.columns([1, 1])
        with col_pdf:
            try:
                pdf_bytes, pdf_filename = ReportService.generate_case_pdf_dossier(current_user, case_id)
                st.download_button(
                    label="📄 Download Official PDF Case Dossier",
                    data=pdf_bytes,
                    file_name=pdf_filename,
                    mime="application/pdf",
                    key=f"btn_pdf_{case_id}",
                    use_container_width=True,
                )
            except Exception as err:
                st.error(f"PDF generation error: {err}")


# =============================================================================
# View 3: First Information Reports (FIRs)
# =============================================================================
def render_firs_view(current_user: Dict[str, Any]) -> None:
    """Render FIR directory and registration with tabbed, uncluttered layout."""
    st.subheader("📑 First Information Reports (FIR Registry)")
    st.caption("Official initial crime disclosures registered under the Code of Criminal Procedure.")

    tab_all, tab_register = st.tabs(["📋 Registered FIRs Ledger", "➕ Lodge New FIR"])

    with tab_register:
        can_create_fir = CaseSecurityValidator.can_create_fir(current_user)
        if can_create_fir:
            st.markdown("##### Register & Lodge First Information Report")
            st.caption("Sworn law enforcement personnel clearance: CONSTABLE, SI, IO, SP, ADMIN authorized.")

            with st.form("form_register_fir"):
                c1, c2 = st.columns(2)
                with c1:
                    fir_no = st.text_input("FIR Number", placeholder="e.g. TS/CYB/2026/0145", help="Unique state FIR registration number")
                    stn = st.selectbox("Assigned Police Station", options=[f"STN-00{i}" for i in range(1, 10)] + ["STN-010"])
                    c_type = st.selectbox("Crime Classification", [
                        "Vehicle Theft", "Cyber Crime & Online Fraud", "Burglary & House Breaking",
                        "Armed Robbery", "Commercial Narcotics Trafficking", "Corporate Financial Embezzlement",
                        "Extortion & Kidnapping", "Homicide Investigation", "Chain Snatching", "Assault"
                    ])
                    comp_name = st.text_input("Complainant Full Name")
                with c2:
                    comp_phone = st.text_input("Complainant Contact / Mobile")
                    loc = st.text_input("Place of Occurrence (Detailed)")
                    desc = st.text_area("Detailed Crime Narrative / Allegations")

                submit_fir_btn = st.form_submit_button("SUBMIT & LODGE FIR", use_container_width=True)

                if submit_fir_btn:
                    if not fir_no.strip() or not comp_name.strip() or not desc.strip():
                        st.error("FIR number, complainant name, and crime narrative are required.")
                    else:
                        try:
                            CaseService.create_fir(current_user, {
                                "fir_number": fir_no.strip(),
                                "station_id": stn,
                                "crime_type": c_type,
                                "complainant_name": comp_name.strip(),
                                "complainant_phone": comp_phone.strip() if comp_phone else "N/A",
                                "place_of_occurrence": loc.strip() if loc else "N/A",
                                "description": desc.strip(),
                                "incident_date": datetime.now(),
                                "reported_date": datetime.now(),
                            })
                            st.success(f"✅ First Information Report **{fir_no}** successfully lodged and persisted to database.")
                            st.rerun()
                        except Exception as err:
                            st.error(f"Failed to register FIR: {err}")
        else:
            st.warning("Your operational role does not possess authorization to register new First Information Reports.")

    with tab_all:
        firs = CaseService.get_firs(current_user)
        if firs:
            df = pd.DataFrame(firs)
            fc1, fc2 = st.columns([3, 1])
            with fc1:
                search_fir = st.text_input("Search FIRs by Number or Complainant", placeholder="e.g. TS/NORTH or Suresh", key="search_fir_input")
            with fc2:
                st.write("")
                st.write("")
                st.caption(f"Total Jurisdictional FIRs: **{len(df)}**")

            if search_fir.strip():
                sf = search_fir.strip().lower()
                df = df[df.apply(lambda r: sf in str(r.get("fir_number", "")).lower() or sf in str(r.get("complainant_name", "")).lower() or sf in str(r.get("crime_type", "")).lower(), axis=1)]

            cols = ["fir_number", "station_id", "crime_type", "complainant_name", "status", "reported_date"]
            avail = [c for c in cols if c in df.columns]
            st.dataframe(df[avail], use_container_width=True, hide_index=True)
        else:
            st.info("No FIRs registered in your jurisdictional scope.")


# =============================================================================
# View 4: Semantic Case Matcher
# =============================================================================
def render_semantic_search_view(current_user: Dict[str, Any]) -> None:
    """Render semantic case search with in-memory model caching."""
    st.subheader("🔎 Semantic Case Matcher: Pattern & MO Intelligence")
    st.caption("Identifies potentially similar cases across stations using Sentence Transformers and Modus Operandi vector embeddings.")

    st.markdown(
        """
        <div class="security-notice" style="border-left-color: #38bdf8;">
            ℹ️ <strong>POLICE INTELLIGENCE DISCLAIMER</strong><br>
            All matches produced by the semantic search engine are classified as 
            <strong>'Potentially Similar Cases (Pending Corroboration)'</strong> based on linguistic and MO patterns.
            They do <em>NOT</em> constitute confirmed connections or legal evidence.
        </div>
        """,
        unsafe_allow_html=True,
    )

    cases = CaseService.get_cases(current_user, limit=300)
    if not cases:
        st.warning("No cases available for semantic comparison.")
        return

    mode = st.radio("Search Mode", ["Compare Existing Case Dossier", "Custom Modus Operandi / Query Search"], horizontal=True)

    matches = []
    if mode == "Compare Existing Case Dossier":
        case_options = {f"{c['case_id']} - {c['title']}": c for c in cases}
        sel_key = st.selectbox("Select Target Case Dossier", options=list(case_options.keys()))
        target_case = case_options[sel_key]

        st.write(f"**Target MO:** {target_case.get('modus_operandi', 'N/A')}")
        if st.button("🚀 Find Potentially Similar Cases"):
            with st.spinner("Analyzing semantic embeddings against case database..."):
                matches = SemanticSearchEngine.find_potentially_similar_cases(
                    target_case_or_text=target_case,
                    candidate_cases=cases,
                    top_k=5,
                    min_threshold=0.15,
                )
    else:
        query_text = st.text_area("Enter Modus Operandi or Crime Narrative Pattern", placeholder="e.g. keyless relay theft of Fortuner using OBD diagnostic device...")
        if st.button("🚀 Execute Semantic Search"):
            if not query_text.strip():
                st.error("Please enter a query.")
            else:
                with st.spinner("Computing cosine similarity..."):
                    matches = SemanticSearchEngine.find_potentially_similar_cases(
                        target_case_or_text=query_text,
                        candidate_cases=cases,
                        top_k=5,
                        min_threshold=0.15,
                    )

    if matches:
        st.markdown(f"### Results: {len(matches)} Potentially Similar Cases")
        for m in matches:
            sim_pct = int(m['similarity_score'] * 100)
            st.markdown(
                f"""
                <div style="background-color: #111a2c; border: 1px solid #1e2e4a; border-left: 5px solid #0284c7; padding: 14px; border-radius: 4px; margin-bottom: 12px;">
                    <div style="display: flex; justify-content: space-between;">
                        <h4 style="margin: 0; color: #f8fafc;">{m['title']} (<code>{m['case_id']}</code>)</h4>
                        <span style="font-weight: 700; color: #38bdf8; font-size: 16px;">{sim_pct}% SIMILARITY</span>
                    </div>
                    <p style="margin: 4px 0; font-size: 12px; color: #94a3b8;">
                        <strong>Crime:</strong> {m['crime_type']} • <strong>Station:</strong> {m['station_id']} • <strong>Status:</strong> {m['status']} • <strong>Engine:</strong> {m['engine_used']}
                    </p>
                    <p style="margin: 6px 0 0 0; font-size: 13px; color: #cbd5e1;">
                        <strong>Modus Operandi:</strong> {m['modus_operandi']}
                    </p>
                    <div style="font-size: 11px; color: #f59e0b; margin-top: 6px;">
                        ⚠️ {m['disclaimer']}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )


# =============================================================================
# View 5: SP Crime Analytics & Geospatial Tactical Intelligence
# =============================================================================
def render_analytics_view(current_user: Dict[str, Any]) -> None:
    """Render dedicated, consolidated Crime Analytics and Geospatial Intelligence Dashboard.

    Accessible EXCLUSIVELY to the Superintendent of Police (SP) role.
    """
    role = current_user.get("role")
    if role != settings.ROLE_SP:
        st.error("🛡️ RESTRICTED ACCESS: The Crime Analytics & Geospatial Command Center is accessible exclusively to the Superintendent of Police (SP).")
        st.info("Your current operational rank does not possess department-wide executive oversight clearance for tactical mapping and precinct analytics.")
        return

    st.subheader("📊 Executive Crime Analytics & Geospatial Command Center")
    st.caption("Consolidated department-wide crime mapping, priority distribution, temporal velocity, and precinct caseload for Superintendent of Police (SP) oversight.")

    # 1. Query real MongoDB data
    db = get_db()
    stations_list = list(db.police_registry.find({}, {"_id": 0}))
    stations_by_id = {s["station_id"]: s for s in stations_list}

    all_cases = list(db.cases.find({}, {"_id": 0}))
    if not all_cases:
        st.warning("No cases recorded in database.")
        return

    df_cases = pd.DataFrame(all_cases)

    # Map each case to latitude and longitude based on station registry coordinates
    latitudes = []
    longitudes = []
    station_names = []

    for _, row in df_cases.iterrows():
        stn_id = row.get("station_id")
        stn = stations_by_id.get(stn_id)
        if not stn:
            for s in stations_list:
                if s.get("name") and (stn_id in s["name"] or s["name"] in str(stn_id)):
                    stn = s
                    break
        if stn and "latitude" in stn and "longitude" in stn:
            # Deterministic micro-jitter so individual incidents scatter realistically across the station's precinct jurisdiction
            c_hash = int(hashlib.md5(str(row.get("case_id", "")).encode()).hexdigest()[:6], 16)
            lat_offset = ((c_hash % 200) - 100) * 0.00015
            lon_offset = (((c_hash // 200) % 200) - 100) * 0.00015
            latitudes.append(stn["latitude"] + lat_offset)
            longitudes.append(stn["longitude"] + lon_offset)
            station_names.append(stn.get("name", "Unknown Station"))
        else:
            latitudes.append(17.4401)
            longitudes.append(78.3489)
            station_names.append("Central Jurisdiction")

    df_cases["latitude"] = latitudes
    df_cases["longitude"] = longitudes
    df_cases["station_name"] = station_names

    # Color coding for PyDeck mapping:
    # Critical: Red, High: Orange, Medium: Blue, Low: Green
    def get_color(prio):
        prio_upper = str(prio).upper()
        if prio_upper == "CRITICAL":
            return [220, 38, 38, 210]
        elif prio_upper == "HIGH":
            return [249, 115, 22, 200]
        elif prio_upper == "MEDIUM":
            return [59, 130, 246, 180]
        else:
            return [16, 185, 129, 170]

    df_cases["color"] = df_cases["priority"].apply(get_color)

    # 2. Executive KPI Summary Ribbon
    total_cases = len(df_cases)
    crit_cases = len(df_cases[df_cases["priority"].isin(["CRITICAL", "HIGH"])])
    under_inv = len(df_cases[df_cases["status"] == "UNDER INVESTIGATION"])
    closed_cases = len(df_cases[df_cases["status"].isin(["CLOSED", "CHARGESHEETED"])])
    resolution_rate = round((closed_cases / total_cases * 100), 1) if total_cases > 0 else 0

    kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
    with kpi1:
        st.markdown(f'<div class="metric-box"><div class="metric-label">Total Department Cases</div><div class="metric-val">{total_cases}</div></div>', unsafe_allow_html=True)
    with kpi2:
        st.markdown(f'<div class="metric-box"><div class="metric-label">High / Critical Alerts</div><div class="metric-val" style="color: #ef4444;">{crit_cases}</div></div>', unsafe_allow_html=True)
    with kpi3:
        st.markdown(f'<div class="metric-box"><div class="metric-label">Under Active Investigation</div><div class="metric-val" style="color: #38bdf8;">{under_inv}</div></div>', unsafe_allow_html=True)
    with kpi4:
        st.markdown(f'<div class="metric-box"><div class="metric-label">Resolution / Closed Rate</div><div class="metric-val" style="color: #10b981;">{resolution_rate}%</div></div>', unsafe_allow_html=True)
    with kpi5:
        st.markdown(f'<div class="metric-box"><div class="metric-label">Monitored Stations</div><div class="metric-val">{len(stations_list)}</div></div>', unsafe_allow_html=True)

    # 3. Interactive Filters
    st.markdown("<hr style='border-color: #1e293b; margin: 12px 0;'>", unsafe_allow_html=True)
    fc1, fc2, fc3, fc4 = st.columns(4)
    with fc1:
        station_filter = st.selectbox("Filter Police Station", ["ALL STATIONS"] + sorted([s["name"] for s in stations_list]), key="sp_flt_station")
    with fc2:
        all_crimes = sorted(list(df_cases["crime_type"].dropna().unique()))
        crime_filter = st.selectbox("Filter Crime Classification", ["ALL CRIMES"] + all_crimes, key="sp_flt_crime")
    with fc3:
        prio_filter = st.selectbox("Filter Priority", ["ALL PRIORITIES", "CRITICAL", "HIGH", "MEDIUM", "LOW"], key="sp_flt_prio")
    with fc4:
        status_filter = st.selectbox("Filter Status", ["ALL STATUSES", "UNDER INVESTIGATION", "OPEN", "CHARGESHEETED", "CLOSED", "COLD_CASE"], key="sp_flt_status")

    # Apply filters
    filtered_df = df_cases.copy()
    if station_filter != "ALL STATIONS":
        filtered_df = filtered_df[filtered_df["station_name"] == station_filter]
    if crime_filter != "ALL CRIMES":
        filtered_df = filtered_df[filtered_df["crime_type"] == crime_filter]
    if prio_filter != "ALL PRIORITIES":
        filtered_df = filtered_df[filtered_df["priority"] == prio_filter]
    if status_filter != "ALL STATUSES":
        filtered_df = filtered_df[filtered_df["status"] == status_filter]

    st.caption(f"Displaying **{len(filtered_df)}** of {total_cases} cases matching filters.")

    # 4. Map Visualizations
    st.markdown("### 🗺️ Geospatial Crime Incident Distribution")
    st.caption("Interactive street-level crime incident mapping across Cyberabad & Hyderabad police jurisdictions.")

    map_tab_tactical, map_tab_native = st.tabs(["🛰️ Tactical Deck Map (3D / High-Contrast)", "🗺️ Streamlit Native Map"])

    with map_tab_tactical:
        df_stn_geo = pd.DataFrame(stations_list)
        df_stn_geo["color"] = [[234, 179, 8, 240]] * len(df_stn_geo)
        df_stn_geo["radius"] = 350

        incidents_layer = pdk.Layer(
            "ScatterplotLayer",
            data=filtered_df,
            get_position=["longitude", "latitude"],
            get_color="color",
            get_radius=180,
            pickable=True,
            auto_highlight=True,
        )

        stations_layer = pdk.Layer(
            "ScatterplotLayer",
            data=df_stn_geo,
            get_position=["longitude", "latitude"],
            get_color="color",
            get_radius="radius",
            pickable=True,
            auto_highlight=True,
        )

        view_state = pdk.ViewState(
            latitude=17.4300,
            longitude=78.4100,
            zoom=11,
            pitch=35,
        )

        deck = pdk.Deck(
            layers=[stations_layer, incidents_layer],
            initial_view_state=view_state,
            tooltip={
                "html": "<b>{title}</b><br/>ID: <code>{case_id}</code><br/>Crime: {crime_type}<br/>Priority: {priority}<br/>Status: {status}<br/>Station: {station_name}",
                "style": {"backgroundColor": "#0d131f", "color": "#f8fafc", "border": "1px solid #1e293b", "fontSize": "12px", "padding": "8px"},
            },
        )
        st.pydeck_chart(deck, use_container_width=True)

        st.markdown(
            """
            <div style="display: flex; gap: 16px; font-size: 12px; margin-top: 4px; color: #94a3b8; flex-wrap: wrap;">
                <div><span style="display: inline-block; width: 10px; height: 10px; background-color: #ef4444; border-radius: 50%; margin-right: 4px;"></span> Critical Priority</div>
                <div><span style="display: inline-block; width: 10px; height: 10px; background-color: #f97316; border-radius: 50%; margin-right: 4px;"></span> High Priority</div>
                <div><span style="display: inline-block; width: 10px; height: 10px; background-color: #3b82f6; border-radius: 50%; margin-right: 4px;"></span> Medium Priority</div>
                <div><span style="display: inline-block; width: 10px; height: 10px; background-color: #10b981; border-radius: 50%; margin-right: 4px;"></span> Low Priority</div>
                <div><span style="display: inline-block; width: 10px; height: 10px; background-color: #eab308; border-radius: 50%; margin-right: 4px;"></span> Police Station Post</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with map_tab_native:
        if not filtered_df.empty:
            st.map(filtered_df[["latitude", "longitude"]], zoom=11)
        else:
            st.info("No matching incident locations to display.")

    # 5. Consolidated Plotly Charts Grouped Together
    st.markdown("<hr style='border-color: #1e293b; margin: 20px 0;'>", unsafe_allow_html=True)
    st.markdown("### 📈 Tactical Crime Analytics & Trends")

    chart_c1, chart_c2 = st.columns(2)

    with chart_c1:
        st.markdown("#### Crime Distribution by Classification")
        crime_counts = filtered_df["crime_type"].value_counts().reset_index()
        crime_counts.columns = ["Crime Classification", "Incidents"]
        fig_crime = px.bar(
            crime_counts,
            x="Incidents",
            y="Crime Classification",
            orientation="h",
            color="Incidents",
            color_continuous_scale="Blues",
        )
        fig_crime.update_layout(
            template="plotly_dark",
            paper_bgcolor="#0d131f",
            plot_bgcolor="#111a2c",
            margin=dict(l=20, r=20, t=30, b=20),
            yaxis=dict(autorange="reversed"),
        )
        st.plotly_chart(fig_crime, use_container_width=True)

    with chart_c2:
        st.markdown("#### Priority Allocation Breakdown")
        prio_counts = filtered_df["priority"].value_counts().reset_index()
        prio_counts.columns = ["Priority", "Count"]
        prio_color_map = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#3b82f6",
            "LOW": "#10b981",
        }
        fig_prio = px.pie(
            prio_counts,
            names="Priority",
            values="Count",
            hole=0.45,
            color="Priority",
            color_discrete_map=prio_color_map,
        )
        fig_prio.update_layout(
            template="plotly_dark",
            paper_bgcolor="#0d131f",
            margin=dict(l=20, r=20, t=30, b=20),
        )
        st.plotly_chart(fig_prio, use_container_width=True)

    # Row 2: Cases Over Time & Station Caseload Pipeline
    chart_c3, chart_c4 = st.columns(2)

    with chart_c3:
        st.markdown("#### Cases Registered Over Time (Temporal Velocity)")
        df_time = filtered_df.copy()
        if "created_at" in df_time.columns and not df_time.empty:
            df_time["Month"] = pd.to_datetime(df_time["created_at"]).dt.strftime("%Y-%m")
            time_counts = df_time.groupby("Month").size().reset_index(name="Registered Cases").sort_values("Month")
            fig_time = px.area(
                time_counts,
                x="Month",
                y="Registered Cases",
                markers=True,
                color_discrete_sequence=["#38bdf8"],
            )
            fig_time.update_layout(
                template="plotly_dark",
                paper_bgcolor="#0d131f",
                plot_bgcolor="#111a2c",
                margin=dict(l=20, r=20, t=30, b=20),
            )
            st.plotly_chart(fig_time, use_container_width=True)
        else:
            st.info("No temporal records available.")

    with chart_c4:
        st.markdown("#### Station Caseload Pipeline & Resolution")
        if not filtered_df.empty:
            stn_status = filtered_df.groupby(["station_id", "status"]).size().reset_index(name="Cases")
            fig_stn = px.bar(
                stn_status,
                x="station_id",
                y="Cases",
                color="status",
                barmode="stack",
                color_discrete_sequence=["#1e3a8a", "#0284c7", "#059669", "#d97706", "#dc2626"],
            )
            fig_stn.update_layout(
                template="plotly_dark",
                paper_bgcolor="#0d131f",
                plot_bgcolor="#111a2c",
                margin=dict(l=20, r=20, t=30, b=20),
            )
            st.plotly_chart(fig_stn, use_container_width=True)
        else:
            st.info("No station status data available.")

    # 6. Incident Drill-down & Ledger Export
    st.markdown("<hr style='border-color: #1e293b; margin: 16px 0;'>", unsafe_allow_html=True)
    st.markdown("#### 📋 Executive Incident Drill-Down")
    display_cols = ["case_id", "title", "crime_type", "priority", "status", "station_name", "created_at"]
    avail_cols = [c for c in display_cols if c in filtered_df.columns]
    st.dataframe(filtered_df[avail_cols], use_container_width=True, hide_index=True)

    csv_text, csv_filename = ReportService.generate_cases_csv(current_user)
    st.download_button(
        label="📥 Download Department Case Ledger (CSV)",
        data=csv_text,
        file_name=csv_filename,
        mime="text/csv",
        use_container_width=True,
    )


# =============================================================================
# View 5b: Dedicated Evidence Vault Module
# =============================================================================
def render_evidence_view(current_user: Dict[str, Any]) -> None:
    """Dedicated Evidence Vault module for managing and uploading evidence."""
    st.subheader("🔬 Evidence Vault & Chain of Custody")
    st.caption("Secure physical and digital evidence management with SHA-256 cryptographic verification and path-traversal protection.")

    cases = CaseService.get_cases(current_user, limit=200)
    if not cases:
        st.warning("No accessible cases found for your operational clearance.")
        return

    case_ids = [c["case_id"] for c in cases]
    default_case = st.session_state.get("selected_case_id")
    default_idx = case_ids.index(default_case) if default_case in case_ids else 0

    col_sel, col_info = st.columns([2, 3])
    with col_sel:
        selected_case_id = st.selectbox(
            "Select Case for Evidence Management",
            options=case_ids,
            index=default_idx,
            key="ev_vault_case_sel",
        )
        st.session_state["selected_case_id"] = selected_case_id

    selected_case = next((c for c in cases if c["case_id"] == selected_case_id), None)
    with col_info:
        if selected_case:
            st.markdown(
                f"""
                <div style="background-color: #111a2c; border: 1px solid #1e2e4a; border-radius: 4px; padding: 10px 14px; margin-top: 4px;">
                    <strong>Case:</strong> {selected_case.get('title')} • <strong>Station:</strong> {selected_case.get('station_id')} • <strong>Lead IO:</strong> {selected_case.get('io_officer_id')}<br>
                    <span style="color: #94a3b8; font-size: 12px;">FIR: {selected_case.get('fir_number')} • Priority: {selected_case.get('priority')} • Status: {selected_case.get('status')}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

    tab_vault, tab_upload, tab_custody = st.tabs([
        "📦 Evidence Inventory",
        "➕ Register & Ingest New Item",
        "⛓️ Auditable Chain of Custody",
    ])

    with tab_vault:
        evidence_list = EvidenceService.get_case_evidence(current_user, selected_case_id)
        if evidence_list:
            st.markdown(f"**Total Registered Evidence Items:** {len(evidence_list)}")
            for ev in evidence_list:
                ev_id = ev.get("evidence_id")
                with st.expander(f"📦 {ev.get('name')} ({ev.get('evidence_type')}) — ID: {ev_id}", expanded=True):
                    c1, c2 = st.columns([3, 1])
                    with c1:
                        st.write(f"**Description:** {ev.get('description') or 'N/A'}")
                        st.write(f"**Current Custodian:** `{ev.get('current_custodian_id')}` • **Storage Location:** {ev.get('storage_location')}")
                        st.code(f"SHA-256: {ev.get('sha256_hash')}", language="text")
                        st.caption(f"MIME Type: {ev.get('mime_type')} • Size: {ev.get('file_size_bytes')} bytes")
                    with c2:
                        try:
                            file_bytes, orig_name, mime = EvidenceService.download_evidence(current_user, ev_id)
                            st.download_button(
                                label="⬇️ Download File",
                                data=file_bytes,
                                file_name=orig_name,
                                mime=mime,
                                key=f"vault_dl_{ev_id}",
                                use_container_width=True,
                            )
                        except Exception as err:
                            st.warning(f"Download unavailable: {err}")
        else:
            st.info(f"No evidence registered yet for case {selected_case_id}.")

    with tab_upload:
        can_write = CaseSecurityValidator.can_access_case(current_user, selected_case, require_write=True)
        if can_write:
            with st.form(f"form_ev_vault_upload_{selected_case_id}", clear_on_submit=True):
                st.markdown("##### Secure Evidence File Ingestion")
                ev_name = st.text_input("Evidence Item Name", placeholder="e.g. CCTV Footages, Stolen Laptop, Forensic Lab Report")
                ev_type = st.selectbox("Evidence Classification", ["DIGITAL_MEDIA", "DOCUMENT", "PHYSICAL", "FORENSIC", "WEAPON"])
                ev_loc = st.text_input("Storage Location", value="Central Evidence Locker, Cyberabad")
                ev_desc = st.text_area("Item Description and Recovery Circumstances")
                uploaded_file = st.file_uploader("Upload Evidence File", type=["mp4", "jpg", "png", "pdf", "txt", "doc", "bin"])
                submit_ev = st.form_submit_button("Ingest & Securely Hash Evidence", use_container_width=True)

                if submit_ev:
                    if not ev_name or not uploaded_file:
                        st.error("Evidence item name and file are required.")
                    else:
                        content = uploaded_file.read()
                        res = EvidenceService.register_evidence(
                            current_user=current_user,
                            case_id=selected_case_id,
                            content=content,
                            original_filename=uploaded_file.name,
                            name=ev_name,
                            evidence_type=ev_type,
                            description=ev_desc,
                            storage_location=ev_loc,
                        )
                        st.success(f"✅ Evidence item '{ev_name}' registered successfully with ID `{res['evidence_id']}`!")
                        st.rerun()
        else:
            st.warning("Your operational role does not possess write clearance to ingest evidence for this case.")

    with tab_custody:
        st.markdown("##### Chain of Custody History")
        custody_entries = EvidenceService.get_case_custody_history(current_user, selected_case_id)
        if custody_entries:
            st.dataframe(pd.DataFrame(custody_entries)[["evidence_id", "action", "action_by", "transfer_to", "reason", "timestamp"]], use_container_width=True, hide_index=True)
        else:
            st.info("No chain of custody logs recorded for this case.")


# =============================================================================
# View 5c: Dedicated Gemini AI Tactical Assistant Module
# =============================================================================
def render_ai_assistant_view(current_user: Dict[str, Any]) -> None:
    """Dedicated Google Gemini AI Tactical Assistant module."""
    st.subheader("🤖 Google Gemini Tactical Intelligence Assistant")
    st.caption("AI-powered investigative analysis grounded strictly on verified MongoDB case facts, FIR records, timeline milestones, and evidence logs.")

    api_key_configured = bool(getattr(settings, "GEMINI_API_KEY", "") or os.getenv("GEMINI_API_KEY", ""))
    if api_key_configured:
        st.success(f"● Gemini Engine Online • Model: `{settings.GEMINI_MODEL}` • Grounding Enforced")
    else:
        st.warning("⚠️ Gemini Engine Offline: `GEMINI_API_KEY` is not set in `.env`. Case dossiers, evidence tracking, and semantic search remain 100% operational.")

    cases = CaseService.get_cases(current_user, limit=200)
    if not cases:
        st.warning("No accessible cases found for your operational clearance.")
        return

    case_ids = [c["case_id"] for c in cases]
    default_case = st.session_state.get("selected_case_id")
    default_idx = case_ids.index(default_case) if default_case in case_ids else 0

    col_c1, col_c2 = st.columns([2, 3])
    with col_c1:
        selected_case_id = st.selectbox(
            "Select Case Dossier for AI Consultation",
            options=case_ids,
            index=default_idx,
            key="ai_view_case_sel",
        )
        st.session_state["selected_case_id"] = selected_case_id

    selected_case = next((c for c in cases if c["case_id"] == selected_case_id), None)
    with col_c2:
        if selected_case:
            st.markdown(
                f"""
                <div style="background-color: #111a2c; border: 1px solid #1e2e4a; border-radius: 4px; padding: 10px 14px; margin-top: 4px;">
                    <strong>{selected_case.get('title')}</strong><br>
                    <span style="color: #94a3b8; font-size: 12px;">FIR: {selected_case.get('fir_number')} • Station: {selected_case.get('station_id')} • Lead IO: {selected_case.get('io_officer_id')}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

    tab_structured, tab_qa, tab_history = st.tabs([
        "🧠 Structured Case Intelligence",
        "💬 Interactive Officer Q&A",
        "📜 Historical AI Consultations",
    ])

    with tab_structured:
        analysis_labels = {
            "CASE_SUMMARY": "📋 Executive Case Summary (Senior Leadership)",
            "INVESTIGATION_BRIEF": "🔍 Tactical Detective Briefing (MO & Leads)",
            "EVIDENCE_SUMMARY": "🔬 Evidence & Forensics Integrity Assessment",
            "TIMELINE_ANALYSIS": "⏱️ Timeline Reconstruction & Chronological Gap Analysis",
            "INVESTIGATIVE_QUESTIONS": "❓ Strategic Interrogation & Inquiry Question Generator",
            "CASE_COMPARISON": "⚖️ Side-by-Side Case Comparison",
        }
        col_type, col_action = st.columns([3, 2])
        with col_type:
            selected_analysis = st.selectbox(
                "Select Intelligence Product",
                options=list(analysis_labels.keys()),
                format_func=lambda x: analysis_labels.get(x, x),
                key=f"sel_ai_product_{selected_case_id}",
            )
        comp_case_id = None
        if selected_analysis == "CASE_COMPARISON":
            other_ids = [c["case_id"] for c in cases if c["case_id"] != selected_case_id]
            if other_ids:
                comp_case_id = st.selectbox("Select Case to Compare Against", options=other_ids, key=f"sel_comp_view_{selected_case_id}")
            else:
                st.info("No other accessible cases available for comparison.")

        with col_action:
            st.write("")
            st.write("")
            run_btn = st.button("⚡ Generate AI Intelligence", key=f"btn_run_ai_view_{selected_case_id}", use_container_width=True)

        if run_btn:
            with st.spinner("Synthesizing verified case dossier facts with Gemini AI..."):
                res = GeminiService.analyze_case(
                    current_user=current_user,
                    case_id=selected_case_id,
                    analysis_type=selected_analysis,
                    comparison_case_id=comp_case_id,
                )
                st.session_state[f"last_ai_result_{selected_case_id}"] = res.to_dict()

        last_res = st.session_state.get(f"last_ai_result_{selected_case_id}")
        if last_res:
            st.markdown("---")
            if last_res.get("status") == "SUCCESS":
                st.markdown(f"#### Verified Intelligence Report: `{last_res.get('analysis_type')}`")
                st.caption(f"Generated in {last_res.get('duration_seconds')}s • Grounded strictly on dossier facts")
                st.markdown(last_res.get("output", ""))
            elif last_res.get("status") == "KEY_MISSING":
                st.info(last_res.get("error_message"))
            else:
                st.error(last_res.get("error_message", "AI processing encountered an error."))

    with tab_qa:
        st.markdown("##### Grounded Officer Investigative Q&A")
        st.caption("Ask questions strictly bounded to verified facts, suspects, statements, and timeline in this case.")
        qa_c1, qa_c2 = st.columns([4, 1])
        with qa_c1:
            q_text = st.text_input("Enter your investigative question", placeholder="e.g. What were the specific actions taken during first response? Who are the alibi witnesses?", key=f"qa_input_view_{selected_case_id}")
        with qa_c2:
            st.write("")
            st.write("")
            qa_ask_btn = st.button("🔍 Inquire", key=f"qa_btn_view_{selected_case_id}", use_container_width=True)

        if qa_ask_btn and q_text.strip():
            with st.spinner("Consulting case dossier facts..."):
                qa_res = GeminiService.analyze_case(
                    current_user=current_user,
                    case_id=selected_case_id,
                    analysis_type="OFFICER_QA",
                    officer_query=q_text.strip(),
                )
                if qa_res.status == "SUCCESS":
                    st.markdown("---")
                    st.markdown("##### AI Grounded Response")
                    st.markdown(qa_res.output)
                else:
                    st.error(qa_res.error_message or "AI inquiry failed.")

    with tab_history:
        st.markdown("##### Historical AI Case Analysis Logs")
        hist = GeminiService.get_analysis_history(current_user, case_id=selected_case_id)
        if hist:
            for h in hist:
                with st.expander(f"📜 {h.get('analysis_type')} — {h.get('created_at')}"):
                    st.write(f"**Officer:** {h.get('officer_id')}")
                    st.markdown(h.get("output", ""))
        else:
            st.info("No prior AI consultation records found for this case.")


# =============================================================================
# View 6: In-App Notifications
# =============================================================================
def render_notifications_view(current_user: Dict[str, Any]) -> None:
    """Render officer in-app notifications and alerts."""
    officer_id = current_user.get("officer_id", "")
    st.subheader(f"🔔 Dispatch Alerts & In-App Notifications: [{officer_id}]")
    st.caption("Automated alerts triggered upon case assignments, status changes, and evidence uploads.")

    col1, col2 = st.columns([4, 1])
    with col2:
        if st.button("Mark All as Read", use_container_width=True):
            NotificationService.mark_all_as_read(officer_id)
            st.success("All alerts marked as read.")
            st.rerun()

    notifs = NotificationService.get_officer_notifications(officer_id, limit=30)
    if not notifs:
        st.info("No active notifications in your dispatch queue.")
        return

    for n in notifs:
        unread_tag = "🔴 NEW" if not n.get("is_read") else "⚪ READ"
        border_col = "#38bdf8" if not n.get("is_read") else "#334155"

        st.markdown(
            f"""
            <div style="background-color: #111a2c; border-left: 4px solid {border_col}; border-top: 1px solid #1e293b; border-right: 1px solid #1e293b; border-bottom: 1px solid #1e293b; padding: 12px; border-radius: 4px; margin-bottom: 10px;">
                <div style="display: flex; justify-content: space-between;">
                    <strong>{n.get('title')}</strong>
                    <span style="font-size: 11px; font-weight: 700; color: #94a3b8;">{unread_tag} • {n.get('event_type')}</span>
                </div>
                <p style="margin: 4px 0; color: #cbd5e1; font-size: 13px;">{n.get('message')}</p>
                <div style="font-size: 11px; color: #64748b;">
                    Case Reference: <code>{n.get('case_id') or 'N/A'}</code> • Timestamp: {n.get('created_at')}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


# =============================================================================
# View 7: Stations & Personnel Directory (Phase 1)
# =============================================================================
def render_stations_view(current_user: Dict[str, Any]) -> None:
    st.subheader("Police Registry: Synthetic Station Directory")
    stations = StationService.get_stations(current_user)
    if stations:
        df = pd.DataFrame(stations)
        display_cols = ["station_id", "station_code", "name", "zone", "district", "contact_phone", "sanctioned_strength"]
        avail = [c for c in display_cols if c in df.columns]
        st.dataframe(df[avail], use_container_width=True, hide_index=True)


def render_officers_view(current_user: Dict[str, Any]) -> None:
    st.subheader("Officer Personnel Roster")
    try:
        officers = UserService.get_officers_list(current_user)
        if officers:
            df = pd.DataFrame(officers)
            cols = ["officer_id", "badge_number", "full_name", "rank", "station_id", "contact_phone", "blood_group"]
            avail = [c for c in cols if c in df.columns]
            st.dataframe(df[avail], use_container_width=True, hide_index=True)
    except UnauthorizedAccessError as err:
        st.error(f"🛡️ ACCESS RESTRICTED: {err}")


def render_audit_logs_view(current_user: Dict[str, Any]) -> None:
    st.subheader("Security & Authentication Audit Trail")
    role = current_user.get("role")
    if role not in [settings.ROLE_ADMIN, settings.ROLE_SP]:
        st.error("🛡️ ACCESS DENIED: Security audit logs restricted to SP and ADMIN.")
        AuditService.log_unauthorized_access(current_user, "audit_logs:view_screen")
        return

    filter_event = st.selectbox(
        "Filter by Event Type",
        options=["ALL", "LOGIN_SUCCESS", "LOGIN_FAILED", "LOGOUT", "UNAUTHORIZED_ACCESS", "ACCOUNT_LOCKED", "CASE_CREATED", "CASE_VIEWED", "EVIDENCE_ADDED", "REPORT_GENERATED"],
    )
    query_event = None if filter_event == "ALL" else filter_event
    logs = AuditService.get_recent_logs(limit=150, event_type=query_event)
    if logs:
        st.dataframe(pd.DataFrame(logs)[["timestamp", "event_type", "officer_id", "role", "status", "ip_address", "details"]], use_container_width=True, hide_index=True)


def render_security_admin_view(current_user: Dict[str, Any]) -> None:
    st.subheader("Security Telemetry & Account Lockout Control")
    try:
        telemetry = UserService.get_security_telemetry(current_user)
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total User Accounts", telemetry["total_users"])
        c2.metric("Locked Accounts", telemetry["locked_users"])
        c3.metric("Total Login Attempts", telemetry["total_login_attempts"])
        c4.metric("Failed Login Attempts", telemetry["failed_login_attempts"])

        users = UserService.get_users_list(current_user)
        locked_users = [u["officer_id"] for u in users if u.get("is_locked")]
        if locked_users:
            selected_officer = st.selectbox("Select Locked Officer to Unlock", options=locked_users)
            if st.button(f"🔓 UNLOCK OFFICER {selected_officer}", use_container_width=True):
                UserService.unlock_user_account(current_user, selected_officer)
                st.success(f"Officer {selected_officer} unlocked.")
                st.rerun()
        else:
            st.info("✅ All officer accounts are currently unlocked.")
    except UnauthorizedAccessError as err:
        st.error(f"🛡️ ACCESS RESTRICTED: {err}")
