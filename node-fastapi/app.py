from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, Header, HTTPException, Query, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

DB_PATH = os.getenv("OPENSHIELD_NODE_DB_PATH", "/data/openshield-node.sqlite3")


def ensure_db() -> sqlite3.Connection:
    db_file = Path(DB_PATH)
    db_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(db_file.parent, 0o700)
    except OSError:
        pass

    conn = sqlite3.connect(str(db_file), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = FULL;")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY,
            schema_version TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            source_integration_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            device_id TEXT,
            data_source TEXT NOT NULL,
            summary TEXT NOT NULL,
            payload TEXT NOT NULL
        );
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            hostname TEXT NOT NULL,
            ip TEXT NOT NULL,
            mac TEXT,
            vendor TEXT,
            interface_name TEXT,
            segment TEXT NOT NULL,
            device_type TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )
    conn.commit()
    return conn


db = ensure_db()


class EventIn(BaseModel):
    eventId: str | None = None
    schemaVersion: str = "openshield.event.v1"
    occurredAt: str | None = None
    sourceIntegrationId: str = "openshield-node"
    eventType: Literal[
        "gateway.discovery",
        "gateway.health",
        "ids.alert",
        "zeek.connection",
        "dns.query",
        "threat.ioc",
        "router.access_attempt",
    ] = "gateway.health"
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    deviceId: str | None = None
    dataSource: Literal["mock", "live"] = "live"
    summary: str = Field(min_length=1)
    payload: dict[str, Any] = Field(default_factory=dict)


class EventBatchIn(BaseModel):
    events: list[EventIn]


class DeviceIn(BaseModel):
    id: str | None = None
    hostname: str = Field(min_length=1)
    ip: str = Field(min_length=1)
    mac: str | None = None
    vendor: str | None = None
    interfaceName: str = "br-lan"
    segment: str = "lan"
    deviceType: Literal["router", "workstation", "mobile", "iot", "server"] = "workstation"


app = FastAPI(
    title="OpenShield Node API",
    version="1.0.0",
    description="Serviço FastAPI de ingestão LAN e persistência SQLite do OpenShield.",
)


@app.get("/", include_in_schema=False)
def root(accept: str | None = Header(default=None)):
    if accept and "text/html" in accept:
        return HTMLResponse(
            content="""<!DOCTYPE html>
<html>
<head><meta http-equiv="refresh" content="0; url=http://localhost:3000/" /></head>
<body><p>OpenShield FastAPI Node running. Redirecting to <a href="http://localhost:3000/">OpenShield UI (port 3000)</a>...</p></body>
</html>"""
        )
    return {
        "status": "ready",
        "service": "openshield-node-fastapi",
        "schemaVersion": "openshield.event.v1",
        "frontendUrl": "http://localhost:3000",
        "health": "/health",
        "docs": "/docs",
    }


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ready",
        "service": "openshield-node-fastapi",
        "schemaVersion": "openshield.event.v1",
        "dbPath": DB_PATH,
    }


@app.get("/api/health", include_in_schema=False)
def api_health() -> dict[str, str]:
    return health()


@app.get("/api/v1/events")
def list_events(limit: int = Query(default=25, ge=1, le=500)) -> dict[str, list[dict[str, Any]]]:
    rows = db.execute(
        """
        SELECT event_id, schema_version, occurred_at, source_integration_id,
               event_type, severity, device_id, data_source, summary, payload
        FROM events
        ORDER BY occurred_at DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    events = [
        {
            "eventId": row["event_id"],
            "schemaVersion": row["schema_version"],
            "occurredAt": row["occurred_at"],
            "sourceIntegrationId": row["source_integration_id"],
            "eventType": row["event_type"],
            "severity": row["severity"],
            "deviceId": row["device_id"],
            "dataSource": row["data_source"],
            "summary": row["summary"],
            "payload": json.loads(row["payload"]),
        }
        for row in rows
    ]
    return {"events": events}


def _store_events(items: list[EventIn]) -> list[dict[str, str]]:
    statuses: list[dict[str, str]] = []
    now_iso = datetime.now(timezone.utc).isoformat()

    for ev in items:
        if ev.schemaVersion != "openshield.event.v1":
            raise HTTPException(
                status_code=400,
                detail=f"Versão de schema não suportada ({ev.schemaVersion}).",
            )
        event_id = ev.eventId or f"ev-{uuid.uuid4().hex[:8]}"
        occurred_at = ev.occurredAt or now_iso
        cur = db.execute(
            """
            INSERT OR IGNORE INTO events (
                event_id, schema_version, occurred_at, source_integration_id,
                event_type, severity, device_id, data_source, summary, payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                ev.schemaVersion,
                occurred_at,
                ev.sourceIntegrationId,
                ev.eventType,
                ev.severity,
                ev.deviceId,
                ev.dataSource,
                ev.summary,
                json.dumps(ev.payload),
            ),
        )
        statuses.append(
            {
                "eventId": event_id,
                "status": "accepted" if cur.rowcount == 1 else "duplicate",
            }
        )

    db.commit()
    return statuses


@app.post("/api/v1/events", status_code=201)
@app.post("/api/v1/ingest/events", status_code=201)
def ingest_events(body: EventIn | EventBatchIn) -> dict[str, Any]:
    items = body.events if isinstance(body, EventBatchIn) else [body]
    statuses = _store_events(items)
    return {"count": len(statuses), "statuses": statuses}


@app.get("/api/v1/devices")
def list_devices() -> dict[str, list[dict[str, Any]]]:
    rows = db.execute(
        """
        SELECT id, hostname, ip, mac, vendor, interface_name, segment, device_type, updated_at
        FROM devices
        ORDER BY updated_at DESC
        """
    ).fetchall()

    devices = [
        {
            "id": row["id"],
            "hostname": row["hostname"],
            "ip": row["ip"],
            "mac": row["mac"],
            "vendor": row["vendor"],
            "interfaceName": row["interface_name"],
            "segment": row["segment"],
            "deviceType": row["device_type"],
            "updatedAt": row["updated_at"],
        }
        for row in rows
    ]
    return {"devices": devices}


@app.post("/api/v1/devices", status_code=201)
def upsert_device(device: DeviceIn) -> dict[str, Any]:
    dev_id = device.id or f"dev-{uuid.uuid4().hex[:8]}"
    now_iso = datetime.now(timezone.utc).isoformat()
    db.execute(
        """
        INSERT INTO devices (id, hostname, ip, mac, vendor, interface_name, segment, device_type, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            hostname = excluded.hostname,
            ip = excluded.ip,
            mac = excluded.mac,
            vendor = excluded.vendor,
            interface_name = excluded.interface_name,
            segment = excluded.segment,
            device_type = excluded.device_type,
            updated_at = excluded.updated_at
        """,
        (
            dev_id,
            device.hostname,
            device.ip,
            device.mac,
            device.vendor or "Descoberto pelo Node",
            device.interfaceName,
            device.segment,
            device.deviceType,
            now_iso,
        ),
    )
    db.commit()
    return {"id": dev_id, "status": "saved"}


class OpenWrtMapIn(BaseModel):
    rawOutput: str | None = None
    netDump: dict[str, Any] | None = None
    hostHints: dict[str, Any] | None = None
    ipNeighText: str | None = None


def _infer_segment(iface: str) -> str:
    cleaned = iface.strip()
    return cleaned if cleaned else "br-lan"


@app.post("/api/v1/openwrt/map-devices", status_code=200)
def map_openwrt_devices(payload: OpenWrtMapIn) -> dict[str, Any]:
    import re

    mapped: list[dict[str, str]] = []
    if payload.ipNeighText or payload.netDump or payload.hostHints:
        dev_to_iface: dict[str, str] = {}
        interfaces = (payload.netDump or {}).get("interface", [])
        if isinstance(interfaces, list):
            for item in interfaces:
                if isinstance(item, dict):
                    iface = str(item.get("interface") or "").strip()
                    l3 = str(item.get("l3_device") or "").strip()
                    if iface and l3 and l3 not in dev_to_iface:
                        dev_to_iface[l3] = iface
            for item in interfaces:
                if isinstance(item, dict):
                    iface = str(item.get("interface") or "").strip()
                    dev = str(item.get("device") or "").strip()
                    if iface and dev and dev not in dev_to_iface:
                        dev_to_iface[dev] = iface

        hints = payload.hostHints or {}
        for line in (payload.ipNeighText or "").splitlines():
            parts = line.strip().split()
            if not parts or not re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", parts[0]):
                continue
            ip = parts[0]
            dev = ""
            mac = ""
            for idx, tok in enumerate(parts):
                if tok == "dev" and idx + 1 < len(parts):
                    dev = parts[idx + 1]
                if tok == "lladdr" and idx + 1 < len(parts):
                    mac = parts[idx + 1].upper()
            if not mac or not dev:
                continue
            hint_entry = hints.get(mac) or hints.get(mac.lower()) or {}
            name = str(hint_entry.get("name") or "").strip() or "(sem-nome)"
            iface = dev_to_iface.get(dev, dev)
            mapped.append({"hostname": name, "mac": mac, "ip": ip, "interfaceName": iface})
    elif payload.rawOutput:
        pattern = re.compile(
            r"^(.*?)\s+((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s+((?:\d{1,3}\.){3}\d{1,3})\s+(\S+)\s*$"
        )
        for line in payload.rawOutput.splitlines():
            m = pattern.match(line.strip())
            if not m:
                continue
            mapped.append(
                {
                    "hostname": m.group(1).strip() or "(sem-nome)",
                    "mac": m.group(2).upper(),
                    "ip": m.group(3).strip(),
                    "interfaceName": m.group(4).strip(),
                }
            )

    if not mapped:
        raise HTTPException(
            status_code=400,
            detail="Nenhum dispositivo válido encontrado no mapeamento OpenWrt.",
        )

    now_iso = datetime.now(timezone.utc).isoformat()
    for item in mapped:
        dev_id = f"owrt-{item['mac'].lower().replace(':', '')}"
        db.execute(
            """
            INSERT INTO devices (id, hostname, ip, mac, vendor, interface_name, segment, device_type, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                hostname = excluded.hostname,
                ip = excluded.ip,
                mac = excluded.mac,
                interface_name = excluded.interface_name,
                segment = excluded.segment,
                updated_at = excluded.updated_at
            """,
            (
                dev_id,
                item["hostname"],
                item["ip"],
                item["mac"],
                "Mapeado via OpenWrt (ubus + ip neigh)",
                item["interfaceName"],
                _infer_segment(item["interfaceName"]),
                "workstation",
                now_iso,
            ),
        )
    db.commit()
    return {"count": len(mapped), "devices": mapped}

