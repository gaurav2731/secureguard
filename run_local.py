from app import *
import routes  # Import routes
import filters  # Import filters

if __name__ == "__main__":
    # Initialize logging
    os.makedirs("logs", exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
    )
    logger = logging.getLogger("secureguard")

    # Initialize database
    init_db()

    # Initialize filters
    filters.init_filters(app)

    # Start background workers
    threading.Thread(target=db_writer_worker, daemon=True).start()
    threading.Thread(target=system_block_worker, daemon=True).start()

    try:
        redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)
        redis_client.ping()
        logger.info("Redis connection successful")
    except redis.RedisError as e:
        logger.warning(f"Redis connection failed, falling back to in-memory counters: {e}")
        redis_client = None

    logger.info("SecureGuard Firewall initialized with real-time protection")
    import os
    logger.info("Starting Flask development server on http://localhost:5000 (dev mode only)")
    if os.environ.get('SECUREGUARD_DEV', '0') == '1':
        app.run(debug=True, host='0.0.0.0', port=5000)
    else:
        logger.info("SECUREGUARD_DEV not set. To start the dev server run: SECUREGUARD_DEV=1 python run_local.py")