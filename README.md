secureguard/
├─ __pycache__/                 # compiled bytecode (gitignore)
├─ logs/                        # runtime logs (rotated in prod)
├─ secureguard/                 # optional package name (if any)
├─ static/                      # static assets for UI
├─ templates/                   # Jinja2 HTML templates
├─ app.py                       # Flask/FastAPI app factory or main app
├─ routes.py                    # API endpoints registration
├─ server.py                    # HTTP server bootstrap
├─ wsgi.py                      # WSGI entrypoint for prod
├─ run.py                       # dev runner (python run.py)
├─ run_local.py                 # local-only dev runner
├─ run.sh                       # shell runner (env + start)
├─ start.py                     # CLI start helper
├─ test.py                      # smoke/integration tests
├─ simple_test.py               # basic sanity tests
├─ unblock.py                   # unblock/allowlist utility
├─ auto_updater.py              # self-update logic (optional)
├─ packet_inspector.py          # packet/flow inspection helpers
├─ ml_detector.py               # ML scoring/anomaly detection
├─ filters.py                   # request/response filters/middleware
├─ config.py                    # base config
├─ basic.py                     # basic/dev settings
├─ production.py                # prod settings
├─ redis_config.py              # redis settings
├─ redis_connection.py          # redis client factory
├─ redis_interface.py           # higher-level redis ops
├─ redis_init.py                # boot-time redis checks/priming
├─ check_redis.py               # CLI to test Redis connectivity
├─ requirements.txt             # Python dependencies
├─ secureguard.db               # SQLite DB (dev/test)
├─ secureguard.db.bak.*         # DB backups
