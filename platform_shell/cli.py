"""``platform-shell`` command line: user admin, registry listing, serving and audit replay.

Passwords are never accepted as command-line arguments (they would land in shell
history and process listings). ``add-user`` reads ``PLATFORM_NEW_USER_PASSWORD``
from the environment, or prompts twice with no echo.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from typing import Sequence

from . import DEFAULT_PORT
from .audit import AuditClient, verify_local_chain
from .config import ConfigError, ShellConfig
from .identity import ROLES, UserStore
from .service_registry import RegistryError, load_registry


def _store(cfg: ShellConfig) -> UserStore:
    return UserStore(cfg.db_path, lockout_threshold=cfg.lockout_threshold, lockout_minutes=cfg.lockout_minutes,
                     min_password_length=cfg.min_password_length)


def _read_password() -> str:
    pw = os.environ.get("PLATFORM_NEW_USER_PASSWORD")
    if pw:
        return pw
    if not sys.stdin.isatty():
        raise SystemExit("no TTY: set PLATFORM_NEW_USER_PASSWORD to supply the password")
    first = getpass.getpass("Password: ")
    if first != getpass.getpass("Repeat password: "):
        raise SystemExit("passwords do not match")
    return first


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="platform-shell", description=__doc__.splitlines()[0])
    ap.add_argument("--db", help="user store path (default PLATFORM_DB or data/platform_shell.db)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init-db", help="create the user store")

    au = sub.add_parser("add-user", help="create a user (password via env or prompt)")
    au.add_argument("user_id")
    au.add_argument("--name", required=True)
    au.add_argument("--roles", required=True, help=f"comma-separated: {', '.join(ROLES)}")
    au.add_argument("--email")

    sub.add_parser("list-users", help="list users and roles")
    ul = sub.add_parser("unlock-user", help="clear a lockout")
    ul.add_argument("user_id")

    ls = sub.add_parser("list-services", help="list descriptors from directories and/or registry.yaml files")
    ls.add_argument("paths", nargs="*", help="default: PLATFORM_SERVICES_DIR or examples/services")
    ls.add_argument("--json", action="store_true")

    sv = sub.add_parser("serve", help="run the gateway (development server)")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=DEFAULT_PORT)

    sub.add_parser("replay-audit", help="push spooled audit events to AuditTrailService")
    sub.add_parser("verify-audit-spool", help="verify the local spool's hash chain")

    args = ap.parse_args(argv)
    try:
        cfg = ShellConfig.from_env()
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2
    if args.db:
        cfg.db_path = args.db

    if args.cmd == "init-db":
        _store(cfg)
        print(f"user store ready at {cfg.db_path}")
        return 0
    if args.cmd == "add-user":
        roles = [r.strip() for r in args.roles.split(",") if r.strip()]
        try:
            u = _store(cfg).create_user(args.user_id, args.name, roles, _read_password(), email=args.email)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        print(f"created {u.user_id} roles={','.join(u.roles)}")
        return 0
    if args.cmd == "list-users":
        for u in _store(cfg).list_users():
            state = "inactive" if not u.active else ("locked" if _store(cfg).is_locked(u) else "active")
            print(f"{u.user_id:30} {','.join(u.roles):30} {state}")
        return 0
    if args.cmd == "unlock-user":
        _store(cfg).unlock(args.user_id)
        print(f"unlocked {args.user_id}")
        return 0
    if args.cmd == "list-services":
        paths = args.paths or [cfg.services_dir or "examples/services"]
        try:
            reg = load_registry(paths)
        except RegistryError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps([d.to_dict() for d in reg.list()], indent=2))
        else:
            for d in reg.list():
                print(f"{d.capability:28} {d.agent:24} gxp={str(d.gxp).lower():5} "
                      f"{d.base_url or '(catalogue only)'}  {d.canonical_repo or ''}")
        return 0
    if args.cmd == "serve":
        from .gateway import create_app

        try:
            app = create_app(cfg)
        except ConfigError as e:
            print(f"config error: {e}", file=sys.stderr)
            return 2
        app.run(host=args.host, port=args.port)
        return 0
    if args.cmd == "replay-audit":
        client = AuditClient(cfg.audit_url, source_system=cfg.source_system, spool_path=cfg.audit_spool_path)
        result = client.replay()
        print(json.dumps(result))
        return 0 if not result["error"] else 1
    if args.cmd == "verify-audit-spool":
        result = verify_local_chain(cfg.audit_spool_path)
        print(json.dumps(result))
        return 0 if result["valid"] else 1
    return 2  # pragma: no cover


if __name__ == "__main__":
    sys.exit(main())
