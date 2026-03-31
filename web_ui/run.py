#!/usr/bin/env python3
"""
FalconHunter Web UI launcher.

Usage:
    python web_ui/run.py [--host HOST] [--port PORT] [--password TOKEN] [--public] [--no-auth]

Defaults:
    host     : 127.0.0.1  (use --public to bind 0.0.0.0 for VPS/nginx use)
    port     : 5000
    password : auto-generated token (stored in web_ui/.auth_token)
"""
import argparse
import os
import sys

# Make sure the project root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FalconHunter Web UI")
    parser.add_argument("--host",     default=None,   help="Bind host (default: 127.0.0.1, or 0.0.0.0 with --public)")
    parser.add_argument("--port",     type=int, default=5000, help="Port (default: 5000)")
    parser.add_argument("--debug",    action="store_true", help="Enable Flask debug mode")
    parser.add_argument("--public",   action="store_true", help="Bind to 0.0.0.0 (for reverse proxy / VPS)")
    parser.add_argument("--password", default=None, help="Set a custom auth token/password")
    parser.add_argument("--no-auth",  action="store_true", help="Disable authentication (localhost trusted mode)")
    args = parser.parse_args()

    # Apply password/token before importing app (which reads env at import time)
    if args.password:
        os.environ["UI_TOKEN"] = args.password
    if args.no_auth:
        os.environ["UI_NO_AUTH"] = "1"

    # Stable Flask secret key — derive from token so sessions survive restarts
    from app import AUTH_TOKEN
    import hashlib
    os.environ.setdefault(
        "FLASK_SECRET",
        hashlib.sha256(AUTH_TOKEN.encode()).hexdigest()
    )

    from app import app, AUTH_TOKEN, AUTH_DISABLED

    bind_host = args.host or ("0.0.0.0" if args.public else "127.0.0.1")

    print()
    print("  ╔══════════════════════════════════════════════════╗")
    print("  ║          FalconHunter Web UI                     ║")
    print("  ╠══════════════════════════════════════════════════╣")
    print(f"  ║  Listening : http://{bind_host}:{args.port:<27}║")
    if AUTH_DISABLED:
        print("  ║  Auth      : DISABLED (no-auth mode)             ║")
    else:
        print(f"  ║  Token     : {AUTH_TOKEN:<39}║")
        print("  ║  Open browser → enter the token above to log in  ║")
    if not args.public and bind_host == "127.0.0.1":
        print("  ╠══════════════════════════════════════════════════╣")
        print("  ║  VPS/SSH tunnel:                                  ║")
        print(f"  ║    ssh -L {args.port}:localhost:{args.port} user@YOUR_VPS         ║")
        print(f"  ║    then open http://localhost:{args.port}                  ║")
    print("  ╚══════════════════════════════════════════════════╝")
    print()

    app.run(host=bind_host, port=args.port, debug=args.debug, threaded=True)
