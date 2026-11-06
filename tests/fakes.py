"""In-process stand-ins for upstream services, so the suite never touches the network."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from flask import Flask, jsonify, request

from platform_shell._vendor.audittrail_chain import ACTIONS, ACTOR_TYPES, GENESIS_HASH, _compute_hash


def fake_audittrail() -> Flask:
    """Mimics AuditTrailService POST /log: FORM fields, hash chain, and HTTP 200 + an
    ``alert alert-bad`` banner when it rejects an event (the real service's behaviour)."""
    app = Flask("fake_audittrail")
    events: list[dict] = []
    app.config["EVENTS"] = events
    app.config["RAW"] = []

    @app.get("/healthz")
    def healthz():
        return "ok", 200

    @app.post("/log")
    def log():
        app.config["RAW"].append({"content_type": request.content_type, "json": request.get_json(silent=True)})
        f = request.form
        src, actor, atype, action = (f.get("source_system", "").strip(), f.get("actor", "").strip(),
                                     f.get("actor_type", ""), f.get("action", ""))
        resource, detail = f.get("resource", "").strip(), f.get("detail", "").strip()
        rel = f.get("related_event_id") or None
        error = None
        if not src or not actor or not resource:
            error = "source_system, actor and resource are required"
        elif atype not in ACTOR_TYPES:
            error = "bad actor_type"
        elif action not in ACTIONS:
            error = "bad action"
        elif rel is not None and not any(e["id"] == int(rel) for e in events):
            error = "related_event_id does not reference an existing event"
        if error:
            return f'<div class="alert alert-bad">{error}</div>', 200
        prev = events[-1]["hash"] if events else GENESIS_HASH
        ts = datetime.now(timezone.utc).isoformat()
        rel_i = int(rel) if rel else None
        h = _compute_hash(prev, ts, src, actor, atype, action, resource, detail, rel_i)
        events.append({"id": len(events) + 1, "ts": ts, "source_system": src, "actor": actor, "actor_type": atype,
                       "action": action, "resource": resource, "detail": detail, "related_event_id": rel_i,
                       "prev_hash": prev, "hash": h})
        return "<html>dashboard</html>", 200

    return app


def verify_events(events: list[dict]) -> bool:
    prev = GENESIS_HASH
    for e in events:
        if e["prev_hash"] != prev:
            return False
        if _compute_hash(e["prev_hash"], e["ts"], e["source_system"], e["actor"], e["actor_type"], e["action"],
                         e["resource"], e["detail"], e["related_event_id"]) != e["hash"]:
            return False
        prev = e["hash"]
    return True


def echo_service(name: str) -> Flask:
    """Upstream that echoes what it received; records every request in app.config['SEEN']."""
    app = Flask(f"echo_{name}")
    app.config["SEEN"] = []

    @app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    @app.route("/<path:path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    def any_path(path: str):
        if path == "healthz":
            return jsonify({"status": "ok", "service": name})
        seen = {"service": name, "method": request.method, "path": "/" + path, "query": request.args.to_dict(),
                "headers": {k: v for k, v in request.headers.items()},
                "body": request.get_data(as_text=True)}
        app.config["SEEN"].append(seen)
        status = 201 if request.method == "POST" else 200
        resp = jsonify(seen)
        resp.status_code = status
        resp.headers["Set-Cookie"] = "upstream=1"
        return resp

    return app


def body(resp) -> dict:
    return json.loads(resp.get_data(as_text=True))
