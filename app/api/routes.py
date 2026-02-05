from typing import Optional
import asyncio
import logging

from fastapi import APIRouter, Depends, Request, Body

from app.models.schemas import (
    MessageEvent,
    MessageResponse,
    ScamIntent,
    HackathonRequest,
    HackathonResponse,
)
from app.core.security import verify_api_key
from app.services.session_manager import session_manager
from app.services.scam_detector import scam_detector
from app.services.intelligence_extractor import intelligence_extractor
from app.services.reply_generator import reply_generator
from app.services.callback_service import callback_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["honeypot"])


# ==============================
# HACKATHON ENDPOINT (PRIMARY)
# ==============================
@router.api_route(
    "/honeypot",
    methods=["GET", "POST", "HEAD"],
    response_model=HackathonResponse,
)
async def hackathon_honeypot(
    request_obj: Request,
    api_key: str = Depends(verify_api_key),
    request: Optional[HackathonRequest] = Body(None),
) -> HackathonResponse:
    """
    Primary hackathon submission endpoint.

    GUARANTEES:
    - Always responds quickly
    - Always returns {status, reply}
    - Supports judge message object format
    - Never blocks on callback
    """

    # ----------------------------
    # GET / HEAD (tester ping)
    # ----------------------------
    if request_obj.method in ["GET", "HEAD"]:
        return HackathonResponse(
            status="success",
            reply="Honeypot API is active",
        )

    # ----------------------------
    # Empty POST body (tester)
    # ----------------------------
    if request is None:
        return HackathonResponse(
            status="success",
            reply="Hello. How can I help you?",
        )

    # ----------------------------
    # SAFE MESSAGE EXTRACTION
    # ----------------------------
    raw_message = request.message
    message_text = ""

    if isinstance(raw_message, dict):
        # Judge format
        message_text = raw_message.get("text", "")
    else:
        # Pydantic object or string
        message_text = getattr(raw_message, "text", "") or str(raw_message)

    if not message_text:
        message_text = "Hello"

    # ----------------------------
    # SESSION MANAGEMENT
    # ----------------------------
    session = session_manager.get_or_create_session(request.sessionId)
    session.add_message("scammer", message_text)

    # ----------------------------
    # SCAM DETECTION (FAST)
    # ----------------------------
    is_scam, scam_intents, confidence = scam_detector.detect(message_text)

    for intent in scam_intents:
        session.add_scam_intent(intent)

    session.add_confidence_score(confidence)

    # ----------------------------
    # INTELLIGENCE EXTRACTION
    # (lightweight, non-blocking)
    # ----------------------------
    intel = intelligence_extractor.extract(message_text)

    session.intelligence.upiIds.extend(intel.upiIds)
    session.intelligence.phoneNumbers.extend(intel.phoneNumbers)
    session.intelligence.urls.extend(intel.urls)
    session.intelligence.bankDetails.extend(intel.bankDetails)
    session.intelligence.emailAddresses.extend(intel.emailAddresses)

    # Deduplicate
    session.intelligence.upiIds = list(set(session.intelligence.upiIds))
    session.intelligence.phoneNumbers = list(set(session.intelligence.phoneNumbers))
    session.intelligence.urls = list(set(session.intelligence.urls))
    session.intelligence.bankDetails = list(set(session.intelligence.bankDetails))
    session.intelligence.emailAddresses = list(set(session.intelligence.emailAddresses))

    # ----------------------------
    # TERMINATION CHECK
    # ----------------------------
    should_terminate, termination_reason = session.should_terminate()

    # ----------------------------
    # REPLY GENERATION (FAST)
    # ----------------------------
    if should_terminate:
        reply = reply_generator.generate_goodbye()
        session.terminate(termination_reason)

        # 🔴 IMPORTANT:
        # Fire callback asynchronously — NEVER await
        asyncio.create_task(callback_service.send_callback(session))
        callback_service.log_summary(session)

        session_manager.delete_session(request.sessionId)
    else:
        reply = reply_generator.generate_reply(
            message_text,
            session.scam_intents,
            session.message_count - 1,
        )

    if not reply:
        reply = "Why is my account being suspended?"

    session.add_message("agent", reply)

    # ----------------------------
    # FINAL RESPONSE (STRICT)
    # ----------------------------
    return HackathonResponse(
        status="success",
        reply=reply,
    )


# ==============================
# LEGACY DEBUG ENDPOINT
# ==============================
@router.post("/v1/message", response_model=MessageResponse)
async def process_message(
    event: MessageEvent,
    api_key: str = Depends(verify_api_key),
) -> MessageResponse:
    """
    Internal debugging endpoint (NOT for hackathon evaluation)
    """

    session = session_manager.get_or_create_session(event.sessionId)
    session.add_message("scammer", event.message)

    is_scam, scam_intents, confidence = scam_detector.detect(event.message)

    for intent in scam_intents:
        session.add_scam_intent(intent)

    session.add_confidence_score(confidence)

    intel = intelligence_extractor.extract(event.message)

    session.intelligence.upiIds.extend(intel.upiIds)
    session.intelligence.phoneNumbers.extend(intel.phoneNumbers)
    session.intelligence.urls.extend(intel.urls)
    session.intelligence.bankDetails.extend(intel.bankDetails)
    session.intelligence.emailAddresses.extend(intel.emailAddresses)

    session.intelligence.upiIds = list(set(session.intelligence.upiIds))
    session.intelligence.phoneNumbers = list(set(session.intelligence.phoneNumbers))
    session.intelligence.urls = list(set(session.intelligence.urls))
    session.intelligence.bankDetails = list(set(session.intelligence.bankDetails))
    session.intelligence.emailAddresses = list(set(session.intelligence.emailAddresses))

    should_terminate, termination_reason = session.should_terminate()

    if should_terminate:
        reply = reply_generator.generate_goodbye()
        should_continue = False

        session.terminate(termination_reason)
        asyncio.create_task(callback_service.send_callback(session))
        callback_service.log_summary(session)

        session_manager.delete_session(event.sessionId)
    else:
        reply = reply_generator.generate_reply(
            event.message,
            session.scam_intents,
            session.message_count - 1,
        )
        should_continue = True

    session.add_message("agent", reply)

    return MessageResponse(
        sessionId=event.sessionId,
        reply=reply,
        scamDetected=is_scam,
        scamIntents=scam_intents if scam_intents else [ScamIntent.NONE],
        confidence=confidence,
        shouldContinue=should_continue,
        extractedIntelligence={
            "upiIds": intel.upiIds,
            "phoneNumbers": intel.phoneNumbers,
            "urls": intel.urls,
            "bankDetails": intel.bankDetails,
            "emailAddresses": intel.emailAddresses,
        },
    )


# ==============================
# HEALTH & CLEANUP
# ==============================
@router.get("/v1/health")
async def health_check():
    return {
        "status": "healthy",
        "active_sessions": session_manager.get_active_session_count(),
    }


@router.post("/v1/cleanup")
async def cleanup_sessions(api_key: str = Depends(verify_api_key)):
    session_manager.cleanup_expired_sessions()
    return {
        "status": "success",
        "active_sessions": session_manager.get_active_session_count(),
    }
