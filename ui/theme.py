"""Command Center Theme and Styling for PACT.

Professional law enforcement command center aesthetic: clean white background, high contrast dark text, navy and slate accents.
"""
import streamlit as st


COMMAND_CENTER_CSS = """
<style>
/* Main App Background & Reset */
.stApp {
    background-color: #ffffff;
    color: #0f172a;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}

/* Base text contrast */
h1, h2, h3, h4, h5, h6, p, span, li, a {
    color: #0f172a;
}

/* Sidebar Styling */
section[data-testid="stSidebar"] {
    background-color: #f8fafc !important;
    border-right: 1px solid #e2e8f0;
}

/* Command Center Header Banner */
.command-header {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-left: 6px solid #1e40af;
    padding: 20px 24px;
    border-radius: 6px;
    margin-bottom: 24px;
    box-shadow: 0 1px 4px rgba(0, 0, 0, 0.06);
}

.command-header h1 {
    color: #0f172a !important;
    font-size: 24px;
    font-weight: 700;
    margin: 0;
    letter-spacing: 0.5px;
    text-transform: uppercase;
}

.command-header p {
    color: #475569 !important;
    font-size: 13px;
    margin: 6px 0 0 0;
    letter-spacing: 0.3px;
}

/* Form Field Labels & Legends - High Contrast Dark Text */
label,
.stTextInput label,
.stSelectbox label,
.stTextArea label,
.stDateInput label,
.stNumberInput label,
.stMultiSelect label,
div[data-testid="stWidgetLabel"] p {
    color: #0f172a !important;
    font-weight: 600 !important;
    font-size: 13px !important;
    letter-spacing: 0.3px !important;
    margin-bottom: 4px !important;
}

/* Officer Profile Card in Sidebar */
.officer-badge-card {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 6px;
    padding: 16px;
    margin-bottom: 16px;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
}

.officer-badge-card .officer-name {
    color: #0f172a !important;
    font-weight: 700;
    font-size: 15px;
    margin-bottom: 4px;
}

.officer-badge-card .officer-id {
    color: #0284c7 !important;
    font-family: monospace;
    font-size: 13px;
    margin-bottom: 8px;
    font-weight: 600;
}

.officer-badge-card strong {
    color: #1e293b !important;
}

/* Role Badges */
.badge-role {
    display: inline-block;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.5px;
    text-transform: uppercase;
}

.badge-ADMIN {
    background-color: #fee2e2;
    color: #991b1b;
    border: 1px solid #f87171;
}

.badge-SP {
    background-color: #dbeafe;
    color: #1e40af;
    border: 1px solid #93c5fd;
}

.badge-SI {
    background-color: #dcfce7;
    color: #166534;
    border: 1px solid #86efac;
}

.badge-INVESTIGATING_OFFICER {
    background-color: #e0e7ff;
    color: #3730a3;
    border: 1px solid #a5b4fc;
}

.badge-CONSTABLE {
    background-color: #f1f5f9;
    color: #334155;
    border: 1px solid #cbd5e1;
}

/* Metric / Stat Card */
.metric-box {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 6px;
    padding: 16px;
    margin-bottom: 14px;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
}

.metric-box .metric-label {
    font-size: 11px;
    color: #64748b !important;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    font-weight: 600;
    margin-bottom: 6px;
}

.metric-box .metric-val {
    font-size: 24px;
    font-weight: 700;
    color: #0f172a !important;
}

/* Data Table & DataFrame Overrides */
div[data-testid="stTable"], div[data-testid="stDataFrame"] {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 6px;
}

/* Security Notice Box */
.security-notice {
    background-color: #fffbeb;
    border-left: 4px solid #f59e0b;
    border-top: 1px solid #fef3c7;
    border-right: 1px solid #fef3c7;
    border-bottom: 1px solid #fef3c7;
    padding: 12px 16px;
    border-radius: 4px;
    font-size: 12px;
    color: #92400e !important;
    margin-bottom: 16px;
    line-height: 1.5;
}

.security-notice strong {
    color: #78350f !important;
}

/* Button Overrides */
div.stButton > button {
    background-color: #1e40af;
    color: #ffffff !important;
    border: 1px solid #1d4ed8;
    border-radius: 4px;
    font-weight: 600;
    padding: 0.5rem 1rem;
    transition: all 0.15s ease-in-out;
}

div.stButton > button:hover {
    background-color: #1d4ed8;
    border-color: #2563eb;
    color: #ffffff !important;
}

div.stButton > button:active {
    background-color: #1e3a8a;
}

/* Inputs, Textareas, Selectboxes */
input, textarea, select {
    background-color: #ffffff !important;
    color: #0f172a !important;
    border: 1px solid #cbd5e1 !important;
    border-radius: 4px !important;
}

input:focus, textarea:focus, select:focus {
    border-color: #2563eb !important;
    outline: none !important;
    box-shadow: 0 0 0 1px #2563eb !important;
}

div[data-baseweb="select"] > div {
    background-color: #ffffff !important;
    border-color: #cbd5e1 !important;
    color: #0f172a !important;
}

div[data-baseweb="popover"], ul[role="listbox"] {
    background-color: #ffffff !important;
    color: #0f172a !important;
}

li[role="option"] {
    background-color: #ffffff !important;
    color: #0f172a !important;
}

li[role="option"]:hover, li[aria-selected="true"] {
    background-color: #f1f5f9 !important;
    color: #1e40af !important;
}

/* Modern Tabs */
button[data-baseweb="tab"] {
    color: #64748b !important;
    font-weight: 600 !important;
    background-color: transparent !important;
    border: none !important;
    padding: 8px 16px !important;
    font-size: 14px !important;
}

button[data-baseweb="tab"][aria-selected="true"] {
    color: #1e40af !important;
    border-bottom: 2px solid #1e40af !important;
}

/* Radio Navigation Items */
div[data-testid="stRadio"] label {
    color: #1e293b !important;
    font-weight: 500 !important;
    font-size: 13px !important;
}

/* Expander */
div[data-testid="stExpander"] {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 4px;
}

div[data-testid="stExpander"] summary {
    color: #0f172a !important;
    font-weight: 600;
}

/* Captions */
.stCaption, [data-testid="stCaptionContainer"] {
    color: #64748b !important;
    font-size: 12px !important;
}

/* Code blocks */
code {
    background-color: #f1f5f9 !important;
    color: #0284c7 !important;
    padding: 2px 4px;
    border-radius: 4px;
}
</style>
"""


def apply_command_center_theme() -> None:
    """Inject Command Center CSS into the Streamlit session."""
    st.markdown(COMMAND_CENTER_CSS, unsafe_allow_html=True)
