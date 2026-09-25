"""In-app notification service for PACT.

Triggers notifications upon case assignments, status changes, and evidence updates.
"""
from datetime import datetime, timezone
import logging
import uuid
from typing import List, Dict, Any, Optional
from pymongo.database import Database
from pymongo.errors import PyMongoError

from database.connection import get_db, get_notifications_col

logger = logging.getLogger("pact.services.notifications")


class NotificationService:
    """Service to create, query, and manage officer alerts and in-app notifications."""

    @staticmethod
    def create_notification(
        recipient_officer_id: str,
        title: str,
        message: str,
        event_type: str,
        case_id: Optional[str] = None,
        db: Optional[Database] = None,
    ) -> bool:
        """Create and store an in-app notification for a designated officer."""
        target_db = db if db is not None else get_db()
        col = get_notifications_col(target_db)

        record = {
            "notification_id": f"NOTIF-{uuid.uuid4().hex[:10].upper()}",
            "recipient_officer_id": recipient_officer_id.upper(),
            "title": title,
            "message": message,
            "event_type": event_type,
            "case_id": case_id,
            "is_read": False,
            "created_at": datetime.now(timezone.utc),
        }

        try:
            col.insert_one(record)
            logger.info("Notification sent to %s: [%s]", recipient_officer_id, title)
            return record
        except PyMongoError as err:
            logger.error("Failed to insert notification for %s: %s", recipient_officer_id, err)
            return None

    @staticmethod
    def get_officer_notifications(
        officer_id: str,
        unread_only: bool = False,
        limit: int = 25,
        db: Optional[Database] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve notifications for an officer sorted newest first."""
        target_db = db if db is not None else get_db()
        col = get_notifications_col(target_db)

        query: Dict[str, Any] = {"recipient_officer_id": officer_id.upper()}
        if unread_only:
            query["is_read"] = False

        try:
            cursor = col.find(query).sort("created_at", -1).limit(limit)
            results = []
            for doc in cursor:
                doc["_id"] = str(doc["_id"])
                results.append(doc)
            return results
        except PyMongoError as err:
            logger.error("Failed to query notifications for %s: %s", officer_id, err)
            return []

    # Alias for API flexibility
    get_user_notifications = get_officer_notifications

    @staticmethod
    def get_unread_count(officer_id: str, db: Optional[Database] = None) -> int:
        """Count unread notifications for an officer."""
        target_db = db if db is not None else get_db()
        col = get_notifications_col(target_db)
        try:
            return col.count_documents({"recipient_officer_id": officer_id.upper(), "is_read": False})
        except PyMongoError as err:
            logger.error("Failed to count unread notifications for %s: %s", officer_id, err)
            return 0

    @staticmethod
    def mark_as_read(notification_id: str, officer_id: Optional[str] = None, db: Optional[Database] = None) -> bool:
        """Mark a notification as read."""
        target_db = db if db is not None else get_db()
        col = get_notifications_col(target_db)
        query: Dict[str, Any] = {"notification_id": notification_id}
        if officer_id:
            query["recipient_officer_id"] = officer_id.upper()
        try:
            res = col.update_one(
                query,
                {"$set": {"is_read": True, "read_at": datetime.now(timezone.utc)}},
            )
            return res.modified_count > 0
        except PyMongoError as err:
            logger.error("Failed to mark notification %s as read: %s", notification_id, err)
            return False

    @staticmethod
    def mark_all_as_read(officer_id: str, db: Optional[Database] = None) -> int:
        """Mark all notifications for an officer as read."""
        target_db = db if db is not None else get_db()
        col = get_notifications_col(target_db)
        try:
            res = col.update_many(
                {"recipient_officer_id": officer_id.upper(), "is_read": False},
                {"$set": {"is_read": True, "read_at": datetime.now(timezone.utc)}},
            )
            return res.modified_count
        except PyMongoError as err:
            logger.error("Failed to mark all notifications as read for %s: %s", officer_id, err)
            return 0
