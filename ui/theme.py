"""Command Center Theme and Styling for PACT.

Professional law enforcement command center aesthetic: deep navy, charcoal, slate.
Zero neon or cyberpunk elements.
"""
import streamlit as st


COMMAND_CENTER_CSS = """
<style>
/* Main App Background & Reset */
.stApp {
    background-color: #0d131f;
    color: #e2e8f0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}

/* Sidebar Styling */
section[data-testid="stSidebar"] {
    background-color: #090e17 !important;
    border-right: 1px solid #1e293b;
}

/* Command Center Header Banner */
.command-header {
    background: linear-gradient(135deg, #101c33 0%, #172a4c 100%);
    border: 1px solid #283e66;
    border-left: 6px solid #2563eb;
    padding: 20px 24px;
    border-radius: 6px;
    margin-bottom: 24px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.35);
}

.command-header h1 {
    color: #f8fafc;
    font-size: 24px;
    font-weight: 700;
    margin: 0;
    letter-spacing: 0.5px;
    text-transform: uppercase;
}

.command-header p {
    color: #94a3b8;
    font-size: 13px;
    margin: 6px 0 0 0;
    letter-spacing: 0.3px;
}

/* Officer Profile Card in Sidebar */
.officer-badge-card {
    background-color: #111a2c;
    border: 1px solid #233554;
    border-radius: 6px;
    padding: 16px;
    margin-bottom: 16px;
}

.officer-badge-card .officer-name {
    color: #f1f5f9;
    font-weight: 700;
    font-size: 15px;
    margin-bottom: 4px;
}

.officer-badge-card .officer-id {
    color: #38bdf8;
    font-family: monospace;
    font-size: 13px;
    margin-bottom: 8px;
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
    background-color: #7f1d1d;
    color: #fecaca;
    border: 1px solid #991b1b;
}

.badge-SP {
    background-color: #1e3a8a;
    color: #bfdbfe;
    border: 1px solid #1d4ed8;
}

.badge-SI {
    background-color: #14532d;
    color: #bbf7d0;
    border: 1px solid #15803d;
}

.badge-INVESTIGATING_OFFICER {
    background-color: #312e81;
    color: #c7d2fe;
    border: 1px solid #4338ca;
}

.badge-CONSTABLE {
    background-color: #334155;
    color: #cbd5e1;
    border: 1px solid #475569;
}

/* Metric / Stat Card */
.metric-box {
    background-color: #111a2c;
    border: 1px solid #1e2e4a;
    border-radius: 6px;
    padding: 16px;
    margin-bottom: 14px;
    box-shadow: 0 2px 6px rgba(0, 0, 0, 0.2);
}

.metric-box .metric-label {
    font-size: 11px;
    color: #94a3b8;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    font-weight: 600;
    margin-bottom: 6px;
}

.metric-box .metric-val {
    font-size: 24px;
    font-weight: 700;
    color: #f8fafc;
}

/* Data Table Overrides */
div[data-testid="stTable"] {
    background-color: #111a2c;
    border: 1px solid #1e2e4a;
    border-radius: 6px;
}

/* Security Notice Box */
.security-notice {
    background-color: #0b1322;
    border-left: 4px solid #f59e0b;
    border-top: 1px solid #1e293b;
    border-right: 1px solid #1e293b;
    border-bottom: 1px solid #1e293b;
    padding: 12px 16px;
    border-radius: 4px;
    font-size: 12px;
    color: #cbd5e1;
    margin-bottom: 16px;
}

/* Button Overrides */
div.stButton > button {
    background-color: #1e3a8a;
    color: #f8fafc;
    border: 1px solid #2563eb;
    border-radius: 4px;
    font-weight: 600;
    padding: 0.5rem 1rem;
    transition: all 0.15s ease-in-out;
}

div.stButton > button:hover {
    background-color: #1d4ed8;
    border-color: #3b82f6;
    color: #ffffff;
}

div.stButton > button:active {
    background-color: #1e40af;
}

/* Inputs */
input, textarea, select {
    background-color: #111a2c !important;
    color: #f8fafc !important;
    border: 1px solid #233554 !important;
}

/* Expander */
div[data-testid="stExpander"] {
    background-color: #111a2c;
    border: 1px solid #1e2e4a;
    border-radius: 4px;
}
</style>
"""


def apply_command_center_theme() -> None:
    """Inject Command Center CSS into the Streamlit session."""
    st.markdown(COMMAND_CENTER_CSS, unsafe_allow_html=True)
