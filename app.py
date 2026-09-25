"""PACT Phase 1: Police Assist Case Trace - Command Intelligence Platform.

Main Streamlit Application Entry Point.
"""
import sys
import logging
import streamlit as st

# Configure page configuration FIRST before any other Streamlit calls
st.set_page_config(
    page_title="PACT • Police Assist Case Trace",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("pact.app")

from pymongo.errors import PyMongoError
from config.settings import settings
from database.connection import MongoDBConnection, DatabaseConnectionError
from database.seed import seed_database
from ui.theme import apply_command_center_theme
from ui.auth_page import render_auth_page
from ui.sidebar import render_sidebar
from ui.dashboard import render_dashboard


def initialize_platform() -> bool:
    """Verify MongoDB connectivity loudly and ensure idempotent database seeding."""
    try:
        # Check connection health - fails loudly if MongoDB is down
        MongoDBConnection.check_health()
    except DatabaseConnectionError as err:
        logger.critical("Platform startup halted: MongoDB connection failed: %s", err)
        st.error(
            f"""
            ### 🚨 CRITICAL SYSTEM FAILURE: MONGODB UNAVAILABLE
            The PACT Police Intelligence Platform requires an active MongoDB database instance at:
            `{settings.MONGO_URI}` (Database: `{settings.MONGO_DB_NAME}`)

            **Error Details:**
            `{err}`

            Please start the local MongoDB service (`mongod` / `net start MongoDB`) and reload.
            """
        )
        st.stop()
        return False

    # Seed synthetic stations and users idempotently on startup
    if not st.session_state.get("db_seeded", False):
        try:
            seed_database()
            st.session_state["db_seeded"] = True
            logger.info("Startup database initialization and seeding verified.")
        except (PyMongoError, RuntimeError, ValueError) as seed_err:
            logger.error("Seeding failed on startup: %s", seed_err)
            st.warning(f"Database seeding check warning: {seed_err}")

    return True


def main() -> None:
    """Application main flow."""
    # Apply Command Center CSS
    apply_command_center_theme()

    # Verify Database Connection & Seeding
    initialize_platform()

    # Session Routing
    current_user = st.session_state.get("authenticated_user")

    if not current_user:
        # Render Officer Login Portal
        render_auth_page()
    else:
        # Render Authenticated Command Center
        active_nav = render_sidebar(current_user)
        render_dashboard(current_user, active_nav)


if __name__ == "__main__":
    main()
