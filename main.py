from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import re
from twilio.rest import Client as TwilioClient

from fastapi import FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.templating import Jinja2Templates

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = os.getenv("TRACKING_DATABASE_PATH", str(BASE_DIR / "tracking.db"))
SESSION_SECRET = os.getenv("TRACKING_SESSION_SECRET", "")
ADMIN_USERNAME = os.getenv("TRACKING_ADMIN_USERNAME", "")
ADMIN_PASSWORD_HASH = os.getenv("TRACKING_ADMIN_PASSWORD_HASH", "")
SYNC_SECRET = os.getenv("TRACKING_SYNC_SECRET", "")
PROESHOP_API_URL = os.getenv("PROESHOP_API_URL", "").strip().rstrip("/")
MAX_WEBHOOK_AGE = 300
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "").strip()
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "").strip()
TWILIO_FROM_NUMBER = os.getenv("TWILIO_FROM_NUMBER", "").strip()
TRACKING_PUBLIC_URL = os.getenv("TRACKING_PUBLIC_URL", "").strip().rstrip("/")

STATUSES = [
    "En preparación",
    "Despachado",
    "En tránsito",
    "En centro logístico",
    "En reparto",
    "Entregado",
    "Incidencia",
]

app = FastAPI(
    title="ProEshop Global Tracking",
    docs_url=None,
    redoc_url=None,
)

# En producción se debe configurar TRACKING_SESSION_SECRET en Railway.
# El fallback temporal solo permite ejecutar el proyecto localmente.
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET or secrets.token_urlsafe(48),
    https_only=bool(os.getenv("RAILWAY_ENVIRONMENT")),
    same_site="lax",
    max_age=8 * 60 * 60,
)

app.mount(
    "/static",
    StaticFiles(directory=str(BASE_DIR / "static")),
    name="static",
)
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Limitador sencillo por instancia.
_RATE_BUCKETS: dict[str, deque[float]] = defaultdict(deque)


def rate_limit(key: str, limit: int, window: int) -> None:
    now = time.monotonic()
    bucket = _RATE_BUCKETS[key]

    while bucket and now - bucket[0] > window:
        bucket.popleft()

    if len(bucket) >= limit:
        raise HTTPException(
            status_code=429,
            detail="Demasiadas solicitudes. Inténtalo más tarde.",
        )

    bucket.append(now)


def client_key(request: Request) -> str:
    # No confiar en X-Forwarded-For arbitrario.
    return request.client.host if request.client else "unknown"


@contextmanager
def db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")

    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS shipments (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              order_ref TEXT NOT NULL UNIQUE,
              tracking_number TEXT NOT NULL UNIQUE,
              carrier TEXT NOT NULL DEFAULT 'ProEshop Logistics',
              origin_city TEXT,
              origin_country TEXT,
              destination_city TEXT,
              destination_country TEXT,
              package_description TEXT,
              estimated_delivery TEXT,
              status TEXT NOT NULL,
              customer_phone TEXT NOT NULL DEFAULT '',
              sms_consent INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tracking_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              shipment_id INTEGER NOT NULL
                REFERENCES shipments(id) ON DELETE CASCADE,
              status TEXT NOT NULL,
              description TEXT NOT NULL,
              city TEXT,
              country TEXT,
              source TEXT NOT NULL,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_events_shipment
            ON tracking_events(shipment_id, id DESC);

            CREATE TABLE IF NOT EXISTS webhook_events (
              event_id TEXT PRIMARY KEY,
              order_ref TEXT NOT NULL,
              received_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sms_outbox (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              event_id TEXT NOT NULL UNIQUE,
              shipment_id INTEGER NOT NULL,
              phone TEXT NOT NULL DEFAULT '',
              consent INTEGER NOT NULL DEFAULT 0,
              tracking_number TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('pending', 'sent', 'failed')),
              attempts INTEGER NOT NULL DEFAULT 0,
              last_error TEXT NOT NULL DEFAULT '',
              retryable INTEGER NOT NULL DEFAULT 0,
              next_attempt_at TEXT,
              lease_until TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              sent_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_sms_outbox_due
            ON sms_outbox(status, retryable, next_attempt_at, lease_until);

            CREATE TABLE IF NOT EXISTS admin_audit (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              action TEXT NOT NULL,
              subject TEXT,
              created_at TEXT NOT NULL
            );
            """
        )
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(shipments)").fetchall()}
        for name, declaration in (("customer_phone", "TEXT NOT NULL DEFAULT ''"), ("sms_consent", "INTEGER NOT NULL DEFAULT 0")):
            if name not in cols:
                conn.execute(f"ALTER TABLE shipments ADD COLUMN {name} {declaration}")


@app.on_event("startup")
async def startup() -> None:
    init_db()
    app.state.sms_outbox_task = asyncio.create_task(sms_outbox_worker())


@app.on_event("shutdown")
async def shutdown() -> None:
    task = getattr(app.state, "sms_outbox_task", None)
    if task:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


def send_tracking_sms(phone: str, consent: bool, tracking_number: str, status: str, description: str = "") -> bool:
    """Send one transactional tracking SMS through Twilio's REST API."""
    import logging

    logger = logging.getLogger("tracking.sms")
    if not consent:
        logger.info("SMS skipped: customer_consent_missing tracking=%s", tracking_number)
        return False
    if not phone:
        logger.warning("SMS skipped: customer_phone_missing tracking=%s", tracking_number)
        return False
    if not (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_FROM_NUMBER):
        logger.error("SMS not configured: Twilio environment variables missing")
        return False
    if not re.fullmatch(r"\+[1-9]\d{7,14}", phone):
        logger.warning("SMS skipped: invalid_E164_phone tracking=%s", tracking_number)
        return False

    tracking_url = (
        f"{TRACKING_PUBLIC_URL}/?q={tracking_number}"
        if TRACKING_PUBLIC_URL else tracking_number
    )
    body = (
        f"ProEshop Logistics: {tracking_number} - {status}. "
        f"{description[:180]} Seguimiento: {tracking_url}"
    )
    endpoint = (
        f"https://api.twilio.com/2010-04-01/Accounts/"
        f"{TWILIO_ACCOUNT_SID}/Messages.json"
    )
    try:
        response = httpx.post(
            endpoint,
            data={"From": TWILIO_FROM_NUMBER, "To": phone, "Body": body[:1500]},
            auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN),
            timeout=15.0,
        )
        if response.status_code == 201:
            logger.info("SMS accepted by Twilio tracking=%s", tracking_number)
            return True

        error_code = None
        try:
            error_code = response.json().get("code")
        except (ValueError, AttributeError):
            pass
        logger.error(
            "Twilio rejected SMS tracking=%s http_status=%s error_code=%s",
            tracking_number, response.status_code, error_code
        )
        return False
    except httpx.HTTPError as exc:
        logger.error(
            "Twilio request failed tracking=%s error_type=%s",
            tracking_number, type(exc).__name__
        )
        return False


def _outbox_error_for_ineligible(phone: str, consent: bool) -> str:
    if not consent:
        return "customer_consent_missing"
    if not phone:
        return "customer_phone_missing"
    if not re.fullmatch(r"\+[1-9]\d{7,14}", phone):
        return "invalid_E164_phone"
    if not (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_FROM_NUMBER):
        return "twilio_not_configured"
    return ""


def enqueue_tracking_sms(conn, event_id: str, shipment_id: int, phone: str, consent: bool,
                         tracking_number: str) -> int:
    stamp = now_iso()
    error = _outbox_error_for_ineligible(phone, consent)
    conn.execute(
        """INSERT OR IGNORE INTO sms_outbox
           (event_id, shipment_id, phone, consent, tracking_number, status,
            attempts, last_error, retryable, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)""",
        (event_id, shipment_id, phone, int(consent), tracking_number,
         "failed" if error else "pending", error, 0 if error else 1, stamp, stamp),
    )
    row = conn.execute("SELECT id FROM sms_outbox WHERE event_id=?", (event_id,)).fetchone()
    return int(row["id"])


def deliver_sms_outbox(outbox_id: int) -> dict[str, Any]:
    """Claim and deliver one SMS. The lease prevents concurrent app instances from sending it twice."""
    stamp = now_iso()
    lease = (datetime.now(timezone.utc) + timedelta(seconds=90)).isoformat(timespec="seconds")
    with db() as conn:
        row = conn.execute("SELECT * FROM sms_outbox WHERE id=?", (outbox_id,)).fetchone()
        if not row:
            return {"sent": False, "attempted": False, "reason": "outbox_not_found"}
        eligible = _outbox_error_for_ineligible(row["phone"], bool(row["consent"]))
        if eligible:
            conn.execute(
                """UPDATE sms_outbox SET status='failed', retryable=0, last_error=?,
                   lease_until=NULL, updated_at=? WHERE id=? AND status!='sent'""",
                (eligible, stamp, outbox_id),
            )
            return {"sent": False, "attempted": False, "reason": eligible}
        if row["status"] == "sent":
            return {"sent": True, "attempted": False, "reason": "sent"}
        due = row["status"] == "pending" or (
            row["status"] == "failed" and bool(row["retryable"])
            and (not row["next_attempt_at"] or row["next_attempt_at"] <= stamp)
        )
        lease_active = row["lease_until"] and row["lease_until"] > stamp
        if not due or lease_active:
            return {"sent": False, "attempted": False, "reason": "retry_scheduled" if row["retryable"] else row["last_error"]}
        changed = conn.execute(
            """UPDATE sms_outbox SET lease_until=?, attempts=attempts+1, updated_at=?
               WHERE id=? AND status!='sent'
                 AND (lease_until IS NULL OR lease_until<=?)""",
            (lease, stamp, outbox_id, stamp),
        ).rowcount
        if not changed:
            return {"sent": False, "attempted": False, "reason": "delivery_in_progress"}
        row = conn.execute("SELECT * FROM sms_outbox WHERE id=?", (outbox_id,)).fetchone()

    sms_sent = send_tracking_sms(
        row["phone"], bool(row["consent"]), row["tracking_number"],
        "Despachado", "Tu pedido fue enviado y ya está disponible para seguimiento."
    )
    completed = now_iso()
    with db() as conn:
        if sms_sent:
            conn.execute(
                """UPDATE sms_outbox SET status='sent', retryable=0, last_error='',
                   next_attempt_at=NULL, lease_until=NULL, sent_at=?, updated_at=?
                   WHERE id=? AND status!='sent'""",
                (completed, completed, outbox_id),
            )
            return {"sent": True, "attempted": True, "reason": "sent"}
        # Transient Twilio failures are retried with capped exponential backoff.
        delay = min(60 * (2 ** min(max(row["attempts"] - 1, 0), 8)), 21600)
        next_attempt = (datetime.now(timezone.utc) + timedelta(seconds=delay)).isoformat(timespec="seconds")
        conn.execute(
            """UPDATE sms_outbox SET status='failed', retryable=1,
               last_error='twilio_request_failed', next_attempt_at=?,
               lease_until=NULL, updated_at=? WHERE id=? AND status!='sent'""",
            (next_attempt, completed, outbox_id),
        )
    return {"sent": False, "attempted": True, "reason": "twilio_request_failed"}


async def sms_outbox_worker():
    """Poll the persistent SQLite outbox from the existing Railway web process."""
    while True:
        try:
            stamp = now_iso()
            with db() as conn:
                rows = conn.execute(
                    """SELECT id FROM sms_outbox
                       WHERE (status='pending' OR (status='failed' AND retryable=1
                              AND (next_attempt_at IS NULL OR next_attempt_at<=?)))
                         AND (lease_until IS NULL OR lease_until<=?)
                       ORDER BY id LIMIT 50""",
                    (stamp, stamp),
                ).fetchall()
            for row in rows:
                await asyncio.to_thread(deliver_sms_outbox, int(row["id"]))
        except asyncio.CancelledError:
            raise
        except Exception:
            import logging
            logging.getLogger("tracking.sms").exception("SMS outbox polling failed")
        await asyncio.sleep(30)


def password_matches(password: str, encoded: str) -> bool:
    try:
        scheme, iterations, salt_hex, digest_hex = encoded.split("$", 3)

        if scheme != "pbkdf2_sha256":
            return False

        iterations_int = int(iterations)
        if iterations_int < 310000:
            return False

        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)

        if len(salt) < 16 or len(expected) != 32:
            return False

        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt,
            iterations_int,
        )
        return hmac.compare_digest(actual, expected)

    except (ValueError, TypeError):
        return False


def new_tracking_number(conn) -> str:
    year = datetime.now(timezone.utc).year

    for _ in range(30):
        candidate = f"PE-{year}-{secrets.token_hex(4).upper()}"

        exists = conn.execute(
            "SELECT 1 FROM shipments WHERE tracking_number=?",
            (candidate,),
        ).fetchone()

        if not exists:
            return candidate

    raise RuntimeError("No fue posible generar una guía única")


def add_event(
    conn,
    shipment_id,
    status,
    description,
    city=None,
    country=None,
    source="admin",
):
    conn.execute(
        """
        INSERT INTO tracking_events
        (shipment_id, status, description, city, country, source, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            shipment_id,
            status,
            description[:500],
            city,
            country,
            source,
            now_iso(),
        ),
    )


def public_record(conn, shipment):
    events = conn.execute(
        """
        SELECT status, description, city, country, source, created_at
        FROM tracking_events
        WHERE shipment_id=?
        ORDER BY id DESC
        LIMIT 50
        """,
        (shipment["id"],),
    ).fetchall()

    return {
        "tracking_number": shipment["tracking_number"],
        "order_ref": shipment["order_ref"],
        "carrier": "ProEshop Logistics",
        "origin": {
            "city": shipment["origin_city"],
            "country": shipment["origin_country"],
        },
        "destination": {
            "city": shipment["destination_city"],
            "country": shipment["destination_country"],
        },
        "package_description": shipment["package_description"],
        "estimated_delivery": shipment["estimated_delivery"],
        "status": shipment["status"],
        "updated_at": shipment["updated_at"],
        "events": [
            {
                "status": event["status"],
                "description": event["description"],
                "location": ", ".join(
                    value
                    for value in (event["city"], event["country"])
                    if value
                ) or None,
                "source_label": (
                    "Actualización administrativa"
                    if event["source"] == "admin"
                    else "Evento recibido de ProEshop"
                ),
                "created_at": event["created_at"],
            }
            for event in events
        ],
    }


def require_admin(request: Request) -> None:
    if not request.session.get("admin"):
        raise HTTPException(status_code=401, detail="No autorizado")


def require_csrf(request: Request, token: str) -> None:
    require_admin(request)
    stored = str(request.session.get("csrf", ""))

    if not stored or not secrets.compare_digest(stored, token):
        raise HTTPException(status_code=403, detail="Solicitud no válida")


def create_from_webhook(payload: dict[str, Any]):
    for key in ("event_id", "order_ref", "status"):
        if not isinstance(payload.get(key), str) or not payload[key].strip():
            raise HTTPException(status_code=422, detail="Datos de integración no válidos")

    # ProEshop creates the guide when the order reaches "Enviado".
    if payload["status"].strip().casefold() != "enviado":
        return {"result": "ignored_status"}

    event_id = payload["event_id"].strip()[:120]
    order_ref = payload["order_ref"].strip()[:80]
    phone = str(payload.get("customer_phone") or "").strip()[:24]
    consent = bool(payload.get("sms_consent"))
    sms_outbox_id = None
    duplicate = False
    result = "created"

    with db() as conn:
        previous = conn.execute(
            "SELECT 1 FROM webhook_events WHERE event_id=?", (event_id,)
        ).fetchone()
        if previous:
            duplicate = True
            existing = conn.execute(
                "SELECT tracking_number FROM shipments WHERE order_ref=?", (order_ref,)
            ).fetchone()
            tracking = existing["tracking_number"] if existing else ""
            queued = conn.execute(
                "SELECT id FROM sms_outbox WHERE event_id=?", (event_id,)
            ).fetchone()
            sms_outbox_id = int(queued["id"]) if queued else None
            result = "duplicate_ignored"
        else:
            shipment = conn.execute(
                "SELECT * FROM shipments WHERE order_ref=?", (order_ref,)
            ).fetchone()
            stamp = now_iso()
            should_send_sms = False

            if shipment:
                tracking = shipment["tracking_number"]
                old_status = str(shipment["status"] or "")
                if phone:
                    conn.execute(
                        """UPDATE shipments SET status=?, customer_phone=?,
                           sms_consent=?, updated_at=? WHERE id=?""",
                        ("Despachado", phone, int(consent), stamp, shipment["id"]),
                    )
                else:
                    conn.execute(
                        "UPDATE shipments SET status=?, updated_at=? WHERE id=?",
                        ("Despachado", stamp, shipment["id"]),
                    )
                if old_status.casefold() != "despachado":
                    add_event(
                        conn, shipment["id"], "Despachado",
                        "Pedido enviado desde ProEshop", source="proeshop"
                    )
                    should_send_sms = True
                result = "updated"
                current = conn.execute(
                    "SELECT id, customer_phone, sms_consent FROM shipments WHERE id=?",
                    (shipment["id"],),
                ).fetchone()
                shipment_id = int(current["id"])
                sms_phone = current["customer_phone"] or ""
                sms_consent = bool(current["sms_consent"])
            else:
                tracking = new_tracking_number(conn)
                conn.execute(
                    """INSERT INTO shipments (
                        order_ref, tracking_number, carrier, origin_city, origin_country,
                        destination_city, destination_country, package_description,
                        estimated_delivery, status, customer_phone, sms_consent, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        order_ref, tracking, "ProEshop Logistics",
                        str(payload.get("origin_city") or "")[:80] or None,
                        str(payload.get("origin_country") or "")[:80] or None,
                        str(payload.get("destination_city") or "")[:80] or None,
                        str(payload.get("destination_country") or "")[:80] or None,
                        str(payload.get("package_description") or "")[:160] or None,
                        str(payload.get("estimated_delivery") or "")[:30] or None,
                        "Despachado", phone, int(consent), stamp, stamp,
                    ),
                )
                shipment_id = int(conn.execute(
                    "SELECT id FROM shipments WHERE order_ref=?", (order_ref,)
                ).fetchone()["id"])
                add_event(
                    conn, shipment_id, "Despachado",
                    "Pedido enviado desde ProEshop", source="proeshop"
                )
                sms_phone = phone
                sms_consent = consent
                should_send_sms = True

            conn.execute(
                "INSERT INTO webhook_events(event_id, order_ref, received_at) VALUES (?, ?, ?)",
                (event_id, order_ref, stamp),
            )
            conn.execute(
                "INSERT INTO admin_audit(action, subject, created_at) VALUES (?, ?, ?)",
                ("proeshop_webhook", order_ref, stamp),
            )
            if should_send_sms:
                sms_outbox_id = enqueue_tracking_sms(
                    conn, event_id, shipment_id, sms_phone, sms_consent, tracking
                )

    if sms_outbox_id is not None:
        delivery = deliver_sms_outbox(sms_outbox_id)
        sms_sent = bool(delivery.get("sent"))
        sms_reason = delivery.get("reason", "unknown")
    else:
        sms_sent = False
        sms_reason = "already_in_despachado_status" if not duplicate else "no_sms_outbox"

    if duplicate and sms_outbox_id is not None and sms_reason == "sent":
        sms_reason = "already_sent"
    return {
        "result": result,
        "tracking_number": tracking,
        "sms_attempted": bool(delivery.get("attempted")) if sms_outbox_id is not None else False,
        "sms_sent": sms_sent,
        "sms_reason": sms_reason,
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "proeshop-global-tracking",
    }


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    # Starlette reciente: request, name y context se pasan por nombre.
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={},
    )


@app.get("/api/tracking/lookup")
def lookup(request: Request, q: str):
    rate_limit("lookup:" + client_key(request), 30, 60)
    value = q.strip().upper()[:100]

    if not value:
        raise HTTPException(
            status_code=404,
            detail="No se encontró información de seguimiento",
        )

    with db() as conn:
        shipment = conn.execute(
            """
            SELECT * FROM shipments
            WHERE upper(tracking_number)=? OR upper(order_ref)=?
            """,
            (value, value),
        ).fetchone()

        if not shipment:
            raise HTTPException(
                status_code=404,
                detail="No se encontró información de seguimiento",
            )

        return public_record(conn, shipment)


@app.get("/admin", response_class=HTMLResponse)
def admin(request: Request):
    if not request.session.get("admin"):
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": None},
        )

    with db() as conn:
        shipments = conn.execute(
            "SELECT * FROM shipments ORDER BY id DESC LIMIT 100"
        ).fetchall()

    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={
            "shipments": shipments,
            "statuses": STATUSES,
        },
    )


@app.post("/admin/login")
def admin_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    rate_limit("admin-login:" + client_key(request), 8, 300)

    if not ADMIN_USERNAME or not ADMIN_PASSWORD_HASH or not SESSION_SECRET:
        raise HTTPException(
            status_code=503,
            detail="El administrador aún no está configurado en Railway.",
        )

    username_ok = secrets.compare_digest(username, ADMIN_USERNAME)
    password_ok = password_matches(password, ADMIN_PASSWORD_HASH)

    if not username_ok or not password_ok:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": "Credenciales incorrectas"},
            status_code=401,
        )

    request.session.clear()
    request.session["admin"] = True
    request.session["csrf"] = secrets.token_urlsafe(32)

    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/logout")
def admin_logout(request: Request):
    require_admin(request)
    request.session.clear()
    return RedirectResponse("/", status_code=303)


@app.post("/admin/shipments")
def manual_create(
    request: Request,
    csrf: str = Form(...),
    order_ref: str = Form(...),
    origin_city: str = Form(""),
    origin_country: str = Form(""),
    destination_city: str = Form(""),
    destination_country: str = Form(""),
    package_description: str = Form(""),
    estimated_delivery: str = Form(""),
):
    require_csrf(request, csrf)
    order_ref = order_ref.strip()[:80]

    if not order_ref:
        raise HTTPException(
            status_code=422,
            detail="Número de pedido obligatorio",
        )

    with db() as conn:
        exists = conn.execute(
            "SELECT 1 FROM shipments WHERE order_ref=?",
            (order_ref,),
        ).fetchone()

        if exists:
            raise HTTPException(
                status_code=409,
                detail="Este pedido ya tiene un envío",
            )

        tracking = new_tracking_number(conn)
        stamp = now_iso()

        conn.execute(
            """
            INSERT INTO shipments (
                order_ref, tracking_number, carrier,
                origin_city, origin_country,
                destination_city, destination_country,
                package_description, estimated_delivery,
                status, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                order_ref,
                tracking,
                "ProEshop Logistics",
                origin_city[:80],
                origin_country[:80],
                destination_city[:80],
                destination_country[:80],
                package_description[:160],
                estimated_delivery[:30],
                "En preparación",
                stamp,
                stamp,
            ),
        )

        shipment_id = conn.execute(
            "SELECT id FROM shipments WHERE order_ref=?",
            (order_ref,),
        ).fetchone()["id"]

        add_event(
            conn,
            shipment_id,
            "En preparación",
            "Envío registrado manualmente por administración",
        )

        conn.execute(
            """
            INSERT INTO admin_audit(action, subject, created_at)
            VALUES (?, ?, ?)
            """,
            ("manual_shipment", order_ref, stamp),
        )

    return RedirectResponse("/admin", status_code=303)


async def notify_proeshop_logistics(order_ref: str, status: str, description: str, city: str, country: str):
    if not PROESHOP_API_URL or not SYNC_SECRET:
        return {"sent": False, "reason": "not_configured"}
    payload = {
        "event_id": f"global-tracking:{order_ref}:{status}:{int(time.time())}:{secrets.token_hex(4)}",
        "order_ref": order_ref,
        "tracking_status": status,
        "description": description[:500],
        "city": city[:80],
        "country": country[:80],
    }
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(time.time()))
    signature = hmac.new(SYNC_SECRET.encode("utf-8"), timestamp.encode("ascii") + b"." + raw, hashlib.sha256).hexdigest()
    headers = {"Content-Type": "application/json", "X-Global-Tracking-Timestamp": timestamp,
               "X-Global-Tracking-Signature": signature}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=5.0)) as client:
            response = await client.post(PROESHOP_API_URL + "/api/integrations/global-tracking/events",
                                         content=raw, headers=headers)
        if response.status_code >= 300:
            return {"sent": False, "reason": f"http_{response.status_code}"}
        try:
            return {"sent": True, "result": response.json()}
        except ValueError:
            return {"sent": True, "result": "accepted"}
    except httpx.HTTPError as exc:
        return {"sent": False, "reason": type(exc).__name__}


@app.post("/admin/shipments/{shipment_id}/events")
async def add_admin_event(
    shipment_id: int,
    request: Request,
    csrf: str = Form(...),
    status: str = Form(...),
    description: str = Form(...),
    city: str = Form(""),
    country: str = Form(""),
    estimated_delivery: str = Form(""),
):
    require_csrf(request, csrf)
    if status not in STATUSES or not description.strip():
        raise HTTPException(status_code=422, detail="Actualización no válida")
    with db() as conn:
        shipment = conn.execute("SELECT * FROM shipments WHERE id=?", (shipment_id,)).fetchone()
        if not shipment:
            raise HTTPException(status_code=404, detail="Envío no encontrado")
        add_event(conn, shipment_id, status, description.strip(), city[:80], country[:80], "admin")
        conn.execute("""UPDATE shipments SET status=?,
            estimated_delivery=COALESCE(NULLIF(?, ''), estimated_delivery), updated_at=? WHERE id=?""",
            (status, estimated_delivery[:30], now_iso(), shipment_id))
        conn.execute("INSERT INTO admin_audit(action, subject, created_at) VALUES (?, ?, ?)",
                     ("admin_event", str(shipment_id), now_iso()))
        order_ref = shipment["order_ref"]
        sms_phone = shipment["customer_phone"] if "customer_phone" in shipment.keys() else ""
        sms_consent = bool(shipment["sms_consent"]) if "sms_consent" in shipment.keys() else False
        tracking_number = shipment["tracking_number"]
    send_tracking_sms(sms_phone, sms_consent, tracking_number, status, description.strip())
    await notify_proeshop_logistics(order_ref, status, description.strip(), city, country)
    return RedirectResponse("/admin", status_code=303)


@app.post("/api/integrations/proeshop/orders")
async def proeshop_webhook(
    request: Request,
    x_proeshop_timestamp: str = Header(default=""),
    x_proeshop_signature: str = Header(default=""),
):
    rate_limit("webhook:" + client_key(request), 120, 60)

    if not SYNC_SECRET:
        raise HTTPException(
            status_code=503,
            detail="Integración no configurada",
        )

    try:
        timestamp = int(x_proeshop_timestamp)
    except ValueError:
        raise HTTPException(
            status_code=401,
            detail="Firma no válida",
        )

    if abs(int(time.time()) - timestamp) > MAX_WEBHOOK_AGE:
        raise HTTPException(
            status_code=401,
            detail="Firma no válida",
        )

    raw = await request.body()
    signed = str(timestamp).encode() + b"." + raw

    expected = hmac.new(
        SYNC_SECRET.encode(),
        signed,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(
        expected,
        x_proeshop_signature.lower(),
    ):
        raise HTTPException(
            status_code=401,
            detail="Firma no válida",
        )

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=400,
            detail="JSON no válido",
        )

    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=422,
            detail="Datos de integración no válidos",
        )

    return create_from_webhook(payload)
