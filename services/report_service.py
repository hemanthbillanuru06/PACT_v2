"""Analytics aggregation and ReportLab PDF/CSV dossier generation service."""
import csv
from datetime import datetime, timezone
import io
import logging
import os
import uuid
from typing import Dict, Any, List, Optional, Tuple
from pymongo.database import Database
from pymongo.errors import PyMongoError
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from config.settings import settings
from database.connection import (
    get_db,
    get_cases_col,
    get_firs_col,
    get_investigation_timeline_col,
    get_suspects_col,
    get_victims_col,
    get_evidence_col,
    get_evidence_custody_col,
    get_reports_col,
)
from services.case_service import CaseSecurityValidator
from services.audit_service import AuditService

logger = logging.getLogger("pact.services.reports")


class ReportService:
    """Service for real MongoDB analytics aggregation and PDF/CSV report generation."""

    @staticmethod
    def get_analytics_metrics(current_user: Dict[str, Any], db: Optional[Database] = None) -> Dict[str, Any]:
        """Aggregate crime and operational metrics from real MongoDB collections."""
        target_db = db if db is not None else get_db()
        cases_col = get_cases_col(target_db)

        # Apply role-based query scope
        role = current_user.get("role")
        user_station = current_user.get("station_id")
        user_officer = current_user.get("officer_id")

        match_stage: Dict[str, Any] = {}
        if role == settings.ROLE_SI:
            match_stage = {"$or": [{"station_id": user_station}, {"io_officer_id": user_officer}]}
        elif role == settings.ROLE_INVESTIGATING_OFFICER:
            match_stage = {"$or": [{"io_officer_id": user_officer}, {"assigned_officers": user_officer}]}

        pipeline_base = [{"$match": match_stage}] if match_stage else []

        try:
            # 1. By Crime Type
            p_crime = pipeline_base + [
                {"$group": {"_id": "$crime_type", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}}
            ]
            crime_counts = list(cases_col.aggregate(p_crime))

            # 2. By Status
            p_status = pipeline_base + [
                {"$group": {"_id": "$status", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}}
            ]
            status_counts = list(cases_col.aggregate(p_status))

            # 3. By Priority
            p_priority = pipeline_base + [
                {"$group": {"_id": "$priority", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}}
            ]
            priority_counts = list(cases_col.aggregate(p_priority))

            # 4. By Station
            p_station = pipeline_base + [
                {"$group": {"_id": "$station_id", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}}
            ]
            station_counts = list(cases_col.aggregate(p_station))

            total_cases = cases_col.count_documents(match_stage)

            return {
                "total_cases": total_cases,
                "by_crime_type": {doc["_id"]: doc["count"] for doc in crime_counts if doc["_id"]},
                "by_status": {doc["_id"]: doc["count"] for doc in status_counts if doc["_id"]},
                "by_priority": {doc["_id"]: doc["count"] for doc in priority_counts if doc["_id"]},
                "by_station": {doc["_id"]: doc["count"] for doc in station_counts if doc["_id"]},
            }

        except PyMongoError as err:
            logger.error("Failed to aggregate analytics: %s", err)
            return {
                "total_cases": 0,
                "by_crime_type": {},
                "by_status": {},
                "by_priority": {},
                "by_station": {},
            }

    @classmethod
    def generate_case_pdf_dossier(
        cls,
        current_user: Dict[str, Any],
        case_id: str,
        db: Optional[Database] = None,
    ) -> Tuple[bytes, str]:
        """Generate an official law enforcement PDF Case Dossier using ReportLab."""
        target_db = db if db is not None else get_db()
        cases_col = get_cases_col(target_db)
        case_doc = cases_col.find_one({"case_id": case_id})
        if not case_doc:
            raise FileNotFoundError(f"Case '{case_id}' not found.")

        # RBAC Check
        CaseSecurityValidator.enforce_case_access(current_user, case_doc, require_write=False, db=target_db)

        # Gather related data
        fir_doc = get_firs_col(target_db).find_one({"fir_number": case_doc.get("fir_number")}) or {}
        suspects = list(get_suspects_col(target_db).find({"case_id": case_id}))
        victims = list(get_victims_col(target_db).find({"case_id": case_id}))
        timeline = list(get_investigation_timeline_col(target_db).find({"case_id": case_id}).sort("timestamp", 1))
        evidence = list(get_evidence_col(target_db).find({"case_id": case_id}))

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            textColor=colors.HexColor("#0f172a"),
            alignment=1,  # Center
        )
        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=13,
            textColor=colors.HexColor("#475569"),
            alignment=1,
        )
        h2_style = ParagraphStyle(
            "Heading2Custom",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=15,
            textColor=colors.HexColor("#1e3a8a"),
            spaceBefore=12,
            spaceAfter=6,
        )
        body_style = ParagraphStyle(
            "BodyCustom",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#1e293b"),
        )

        story = []

        # Header Banner
        story.append(Paragraph("STATE POLICE DEPARTMENT • P.A.C.T. INTELLIGENCE", subtitle_style))
        story.append(Paragraph("CONFIDENTIAL CASE INVESTIGATION DOSSIER", title_style))
        story.append(Spacer(1, 4))
        story.append(Paragraph(f"Generated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} • Author: {current_user.get('officer_id')} ({current_user.get('role')})", subtitle_style))
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#1e3a8a"), spaceAfter=14))

        # Basic Info Table
        info_data = [
            [
                Paragraph("<b>Case ID:</b>", body_style),
                Paragraph(str(case_doc.get("case_id")), body_style),
                Paragraph("<b>FIR Number:</b>", body_style),
                Paragraph(str(case_doc.get("fir_number")), body_style),
            ],
            [
                Paragraph("<b>Crime Type:</b>", body_style),
                Paragraph(str(case_doc.get("crime_type")), body_style),
                Paragraph("<b>Status:</b>", body_style),
                Paragraph(str(case_doc.get("status")), body_style),
            ],
            [
                Paragraph("<b>Priority:</b>", body_style),
                Paragraph(str(case_doc.get("priority")), body_style),
                Paragraph("<b>Station:</b>", body_style),
                Paragraph(str(case_doc.get("station_id")), body_style),
            ],
            [
                Paragraph("<b>Lead IO:</b>", body_style),
                Paragraph(str(case_doc.get("io_officer_id")), body_style),
                Paragraph("<b>Location:</b>", body_style),
                Paragraph(str(case_doc.get("location", "N/A")), body_style),
            ],
        ]
        info_table = Table(info_data, colWidths=[80, 180, 80, 180])
        info_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(info_table)
        story.append(Spacer(1, 14))

        # Executive Summary & Modus Operandi
        story.append(Paragraph("1. Executive Summary", h2_style))
        story.append(Paragraph(case_doc.get("summary", "No summary recorded."), body_style))
        story.append(Spacer(1, 8))

        story.append(Paragraph("2. Modus Operandi", h2_style))
        story.append(Paragraph(case_doc.get("modus_operandi", "No modus operandi documented."), body_style))
        story.append(Spacer(1, 12))

        # Suspects Table
        story.append(Paragraph(f"3. Identified Suspects ({len(suspects)})", h2_style))
        if suspects:
            s_rows = [[
                Paragraph("<b>Name</b>", body_style),
                Paragraph("<b>Alias</b>", body_style),
                Paragraph("<b>Status</b>", body_style),
                Paragraph("<b>Priors</b>", body_style),
            ]]
            for s in suspects:
                s_rows.append([
                    Paragraph(s.get("name", "Unknown"), body_style),
                    Paragraph(s.get("alias", "-"), body_style),
                    Paragraph(s.get("status", "SUSPECTED"), body_style),
                    Paragraph(s.get("prior_convictions", "None"), body_style),
                ])
            s_table = Table(s_rows, colWidths=[140, 100, 120, 160])
            s_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(s_table)
        else:
            story.append(Paragraph("No suspects currently cataloged in this dossier.", body_style))
        story.append(Spacer(1, 12))

        # Evidence Catalog
        story.append(Paragraph(f"4. Physical & Digital Evidence ({len(evidence)})", h2_style))
        if evidence:
            ev_rows = [[
                Paragraph("<b>Evidence ID</b>", body_style),
                Paragraph("<b>Item Name</b>", body_style),
                Paragraph("<b>Type</b>", body_style),
                Paragraph("<b>Custodian</b>", body_style),
                Paragraph("<b>SHA-256</b>", body_style),
            ]]
            for ev in evidence:
                sha_short = (ev.get("sha256_hash") or "N/A")[:12] + "..."
                ev_rows.append([
                    Paragraph(ev.get("evidence_id", ""), body_style),
                    Paragraph(ev.get("name", ""), body_style),
                    Paragraph(ev.get("evidence_type", ""), body_style),
                    Paragraph(ev.get("current_custodian_id", ""), body_style),
                    Paragraph(sha_short, body_style),
                ])
            ev_table = Table(ev_rows, colWidths=[100, 140, 100, 80, 100])
            ev_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(ev_table)
        else:
            story.append(Paragraph("No evidence logged.", body_style))
        story.append(Spacer(1, 12))

        # Investigation Milestones Timeline
        story.append(Paragraph(f"5. Chronological Investigation Timeline ({len(timeline)})", h2_style))
        if timeline:
            tl_rows = [[
                Paragraph("<b>Date / Time</b>", body_style),
                Paragraph("<b>Event Type</b>", body_style),
                Paragraph("<b>Milestone Details</b>", body_style),
            ]]
            for t in timeline[:10]:  # Cap at 10 for neat PDF layout
                ts_str = t.get("timestamp").strftime("%Y-%m-%d %H:%M") if isinstance(t.get("timestamp"), datetime) else str(t.get("timestamp"))
                tl_rows.append([
                    Paragraph(ts_str, body_style),
                    Paragraph(t.get("event_type", ""), body_style),
                    Paragraph(f"<b>{t.get('title', '')}</b>: {t.get('description', '')}", body_style),
                ])
            tl_table = Table(tl_rows, colWidths=[110, 100, 310])
            tl_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(tl_table)

        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()

        filename = f"dossier_{case_id}_{uuid.uuid4().hex[:6]}.pdf"

        # Log audit event
        AuditService.log_event(
            event_type=settings.AUDIT_REPORT_GENERATED,
            officer_id=current_user.get("officer_id"),
            role=current_user.get("role"),
            details={"case_id": case_id, "report_type": "PDF_CASE_DOSSIER", "filename": filename},
            status="SUCCESS",
            db=target_db,
        )

        return pdf_bytes, filename

    @classmethod
    def generate_cases_csv(
        cls,
        current_user: Dict[str, Any],
        station_id: Optional[str] = None,
        db: Optional[Database] = None,
    ) -> Tuple[str, str]:
        """Export authorized case registry to CSV."""
        target_db = db if db is not None else get_db()
        cases_col = get_cases_col(target_db)

        role = current_user.get("role")
        user_station = current_user.get("station_id")
        user_officer = current_user.get("officer_id")

        query: Dict[str, Any] = {}
        if role == settings.ROLE_SI:
            query = {"$or": [{"station_id": user_station}, {"io_officer_id": user_officer}]}
        elif role == settings.ROLE_INVESTIGATING_OFFICER:
            query = {"$or": [{"io_officer_id": user_officer}, {"assigned_officers": user_officer}]}
        elif station_id and role in [settings.ROLE_ADMIN, settings.ROLE_SP]:
            query = {"station_id": station_id}

        cases = list(cases_col.find(query, {"_id": 0}).sort("case_id", 1))

        output = io.StringIO()
        fieldnames = [
            "case_id", "fir_number", "title", "crime_type", "priority",
            "status", "station_id", "io_officer_id", "location", "created_at"
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()

        for c in cases:
            c_row = {**c}
            if isinstance(c_row.get("created_at"), datetime):
                c_row["created_at"] = c_row["created_at"].isoformat()
            writer.writerow(c_row)

        csv_text = output.getvalue()
        output.close()

        filename = f"pact_cases_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"

        AuditService.log_event(
            event_type=settings.AUDIT_REPORT_GENERATED,
            officer_id=current_user.get("officer_id"),
            role=current_user.get("role"),
            details={"report_type": "CSV_CASE_EXPORT", "record_count": len(cases)},
            status="SUCCESS",
            db=target_db,
        )

        return csv_text, filename
