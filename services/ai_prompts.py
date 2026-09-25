"""Prompt templates, system instructions, and constraints for PACT Phase 3 Gemini AI Integration."""
from typing import Dict, Any, List, Optional
import json

SYSTEM_INSTRUCTION = """You are PACT-AI, an advanced law enforcement investigative assistance assistant for police officers and investigators.

STRICT OPERATIONAL RULES:
1. GROUNDING: Base all analyses, summaries, and answers STRICTLY AND ONLY on the provided case data, FIR records, timeline entries, evidence logs, notes, and entity files.
2. NO HALLUCINATION: Do NOT invent, assume, or fabricate any facts, suspects, vehicles, phone numbers, locations, timestamps, evidence, or events.
3. NO LEGAL GUILT: Do NOT assert, declare, or conclude legal guilt. Maintain objective investigative language (e.g., 'alleged', 'named as suspect', 'under inquiry').
4. SIMILARITY IS NOT PROOF: When analyzing similarities between cases or patterns, NEVER declare them as 'confirmed connections'. Always classify them as 'Potentially Similar Patterns (Pending Corroboration)'.
5. MISSING INFORMATION: If information is missing, ambiguous, or not present in the dossier, explicitly flag it as 'MISSING DATA / UNVERIFIED' rather than speculating.
6. MANDATORY DISCLAIMER: Every response MUST conclude with the exact disclaimer:
   "AI-generated investigative assistance based on available case data. Verify against source records."
"""

MANDATORY_DISCLAIMER = "AI-generated investigative assistance based on available case data. Verify against source records."


class AIPromptBuilder:
    """Builder for structured investigative prompts ensuring strict isolation and grounding."""

    PROMPT_VERSION = "3.0.0"

    @staticmethod
    def _format_case_context(case_data: Dict[str, Any]) -> str:
        """Serialize case dossier and associated entities into structured, readable text."""
        case_info = case_data.get("case", {})
        fir_info = case_data.get("fir", {})
        suspects = case_data.get("suspects", [])
        victims = case_data.get("victims", [])
        complainants = case_data.get("complainants", [])
        witnesses = case_data.get("witnesses", [])
        property_items = case_data.get("property_items", [])
        evidence_items = case_data.get("evidence", [])
        timeline_events = case_data.get("timeline", [])
        case_notes = case_data.get("notes", [])

        lines = [
            f"=== CASE DOSSIER: {case_info.get('case_id', 'N/A')} ===",
            f"Title: {case_info.get('title', 'N/A')}",
            f"FIR Number: {case_info.get('fir_number', 'N/A')}",
            f"Crime Type: {case_info.get('crime_type', 'N/A')}",
            f"Priority: {case_info.get('priority', 'N/A')}",
            f"Status: {case_info.get('status', 'N/A')}",
            f"Station: {case_info.get('station_id', 'N/A')}",
            f"Lead IO: {case_info.get('io_officer_id', 'N/A')}",
            f"Location: {case_info.get('location', 'N/A')}",
            f"Summary: {case_info.get('summary', 'N/A')}",
            f"Modus Operandi: {case_info.get('modus_operandi', 'N/A')}",
            "",
            "=== FIR DETAILS ===",
            f"FIR Reported Date: {fir_info.get('reported_date', 'N/A')}",
            f"Incident Date: {fir_info.get('incident_date', 'N/A')}",
            f"Place of Occurrence: {fir_info.get('place_of_occurrence', 'N/A')}",
            f"FIR Description: {fir_info.get('description', 'N/A')}",
            "",
            f"=== SUSPECTS ({len(suspects)}) ===",
        ]
        for s in suspects:
            lines.append(f"- Name: {s.get('name', 'N/A')}, Alias: {s.get('alias', 'None')}, Status: {s.get('status', 'N/A')}, Description: {s.get('physical_description', 'N/A')}, Priors: {s.get('prior_convictions', 'None')}")

        lines.append(f"\n=== COMPLAINANTS ({len(complainants)}) ===")
        for c in complainants:
            lines.append(f"- Name: {c.get('name', 'N/A')}, Phone: {c.get('contact_phone', 'N/A')}, Statement: {c.get('statement_summary', 'N/A')}")

        lines.append(f"\n=== VICTIMS ({len(victims)}) ===")
        for v in victims:
            lines.append(f"- Name: {v.get('name', 'N/A')}, Injury Status: {v.get('injury_status', 'None')}, Statement: {v.get('statement_summary', 'N/A')}")

        lines.append(f"\n=== WITNESSES ({len(witnesses)}) ===")
        for w in witnesses:
            lines.append(f"- Name: {w.get('name', 'N/A')}, Deposition: {w.get('deposition_summary', 'N/A')}, Protection: {w.get('protective_custody', False)}")

        lines.append(f"\n=== SEIZED PROPERTY ({len(property_items)}) ===")
        for p in property_items:
            lines.append(f"- Item: {p.get('item_name', 'N/A')}, Type: {p.get('item_type', 'N/A')}, Status: {p.get('custody_status', 'N/A')}, Details: {p.get('description', 'N/A')}")

        lines.append(f"\n=== DIGITAL & PHYSICAL EVIDENCE ({len(evidence_items)}) ===")
        for e in evidence_items:
            lines.append(f"- Evidence ID: {e.get('evidence_id', 'N/A')}, Type: {e.get('evidence_type', 'N/A')}, Name: {e.get('original_filename', 'N/A')}, SHA-256: {e.get('sha256_hash', 'N/A')}")

        lines.append(f"\n=== INVESTIGATION TIMELINE ({len(timeline_events)}) ===")
        for t in timeline_events:
            lines.append(f"- [{t.get('timestamp', 'N/A')}] ({t.get('event_type', 'N/A')}) {t.get('title', 'N/A')}: {t.get('description', 'N/A')}")

        lines.append(f"\n=== CASE DIARY & NOTES ({len(case_notes)}) ===")
        for n in case_notes:
            # Skip confidential notes if marked
            if n.get("category") == "CONFIDENTIAL" and not case_data.get("include_confidential", False):
                continue
            lines.append(f"- [{n.get('created_at', 'N/A')}] ({n.get('category', 'GENERAL')}) Officer {n.get('officer_id', 'N/A')}: {n.get('note_text', 'N/A')}")

        return "\n".join(lines)

    @classmethod
    def build_case_summary_prompt(cls, case_data: Dict[str, Any]) -> str:
        """Prompt for concise executive summary of the case dossier."""
        ctx = cls._format_case_context(case_data)
        return f"""{ctx}

TASK: Provide a concise, highly structured Executive Case Summary for Senior Leadership.
Include:
1. Primary Incident Overview (What happened, when, where)
2. Suspects & Persons of Interest (Current status)
3. Key Evidence Recovered
4. Immediate Investigation Status & Bottlenecks
5. Missing Data / Unverified Points

Remember to ground strictly on the data above and conclude with the mandatory disclaimer."""

    @classmethod
    def build_investigation_brief_prompt(cls, case_data: Dict[str, Any]) -> str:
        """Prompt for a comprehensive investigative briefing for incoming detectives or superiors."""
        ctx = cls._format_case_context(case_data)
        return f"""{ctx}

TASK: Formulate a tactical Investigation Briefing for Detectives.
Include:
1. Modus Operandi & Technical Signatures (Analyze toolmarks, method, technical MO)
2. Timeline Coherence (Consistency between complainant report, incident time, and police actions)
3. Persons Under Investigation & Associational Links
4. Evidence Analysis & Forensics Priorities
5. Actionable Next Steps & Outstanding Subpoenas/Warrants
6. Explicitly Highlight Missing Information

Remember to ground strictly on the data above and conclude with the mandatory disclaimer."""

    @classmethod
    def build_evidence_summary_prompt(cls, case_data: Dict[str, Any]) -> str:
        """Prompt focusing on evidence items, forensic state, and chain of custody integrity."""
        ctx = cls._format_case_context(case_data)
        return f"""{ctx}

TASK: Conduct an Evidence & Forensic Inventory Assessment.
Include:
1. Inventory of Physical & Digital Evidence Cataloged
2. Chain of Custody & Cryptographic Integrity Check (SHA-256 validation status)
3. Evidentiary Weight & Link to Modus Operandi
4. Critical Missing Forensics (e.g. CCTV not collected, call data records missing)

Remember to ground strictly on the data above and conclude with the mandatory disclaimer."""

    @classmethod
    def build_timeline_analysis_prompt(cls, case_data: Dict[str, Any]) -> str:
        """Prompt for chronological gap analysis and alibi verification."""
        ctx = cls._format_case_context(case_data)
        return f"""{ctx}

TASK: Perform a Chronological Timeline & Gap Analysis.
Include:
1. Chronological Event Sequence Reconstruction
2. Delay Analysis (Time elapsed between incident occurrence and official FIR registration)
3. Investigation Pacing (Milestones from first response to current status)
4. Critical Unaccounted Gaps in Time
5. Suspect Alibi Windows

Remember to ground strictly on the data above and conclude with the mandatory disclaimer."""

    @classmethod
    def build_similar_case_explanation_prompt(cls, primary_case: Dict[str, Any], candidate_case: Dict[str, Any]) -> str:
        """Prompt for explaining why two cases exhibit similar MO patterns."""
        p_ctx = cls._format_case_context(primary_case)
        c_ctx = cls._format_case_context(candidate_case)
        return f"""PRIMARY CASE UNDER INVESTIGATION:
{p_ctx}

CANDIDATE COMPARISON CASE:
{c_ctx}

TASK: Compare the Modus Operandi and circumstantial factors of these two cases.
RULES:
- Do NOT declare the cases as 'connected' or 'perpetrated by the same person'.
- Frame findings strictly as 'Potentially Similar Patterns (Pending Corroboration)'.
- Outline:
  1. Specific Overlapping Elements (crime type, vehicle/target selection, timing, tool/method)
  2. Notable Distinguishing Differences
  3. Recommended Verification Steps (forensic cross-matching, alibi verification)

Remember to conclude with the mandatory disclaimer."""

    @classmethod
    def build_investigative_questions_prompt(cls, case_data: Dict[str, Any]) -> str:
        """Prompt to generate strategic interrogation and inquiry questions."""
        ctx = cls._format_case_context(case_data)
        return f"""{ctx}

TASK: Generate a strategic list of Investigative & Interrogation Questions.
Categories:
1. Questions for Complainant / Witnesses (to clarify timeline and missing details)
2. Questions for Primary Suspect (targeting Modus Operandi, key alibi windows, technical tools)
3. Technical Inquiries for Service Providers (telecom, vehicle telematics, banking)
4. Unresolved Inconsistencies that require urgent explanation

Remember to ground strictly on the data above and conclude with the mandatory disclaimer."""

    @classmethod
    def build_case_comparison_prompt(cls, case_a: Dict[str, Any], case_b: Dict[str, Any]) -> str:
        """Prompt for side-by-side comparative analysis of two cases."""
        ctx_a = cls._format_case_context(case_a)
        ctx_b = cls._format_case_context(case_b)
        return f"""CASE A:
{ctx_a}

CASE B:
{ctx_b}

TASK: Provide a Side-by-Side Comparative Matrix and Analysis between Case A and Case B.
Include:
1. Target Demographics & Locations
2. Entry/Theft/Execution Mechanics
3. Suspect Profiles and Physical Descriptions Comparison
4. Points of Convergence & Divergence
5. Disclaimers: Highlight that any correlation is strictly circumstantial and unproven.

Remember to conclude with the mandatory disclaimer."""

    @classmethod
    def build_officer_qa_prompt(cls, case_data: Dict[str, Any], officer_query: str) -> str:
        """Prompt for interactive conversational Q&A bounded strictly to case records."""
        ctx = cls._format_case_context(case_data)
        return f"""{ctx}

OFFICER INVESTIGATION QUERY:
"{officer_query}"

TASK: Answer the officer's query using ONLY the verified facts from the case dossier above.
If the dossier does not contain the answer, explicitly state:
"The current case records do not contain information regarding this inquiry."
Do not speculate or extrapolate beyond verified entries.

Remember to conclude with the mandatory disclaimer."""
