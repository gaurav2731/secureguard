import sqlite3
import subprocess
from redis import Redis
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('unblock')

def unblock_ip(ip):
    # 1. Remove Windows Firewall rule
    try:
        cmd = f'netsh advfirewall firewall delete rule name="SECUREGUARD_BLOCK_{ip.replace(".", "_")}"'
        subprocess.run(cmd, shell=True)
        logger.info(f"Attempted to remove firewall rule for {ip}")
    except Exception as e:
        logger.error(f"Failed to remove firewall rule: {e}")

    # 2. Remove from SQLite database
    try:
        db_file = "secureguard.db"
        if os.path.exists(db_file):
            conn = sqlite3.connect(db_file)
            conn.execute('CREATE TABLE IF NOT EXISTS blocked_ips (id INTEGER PRIMARY KEY, ip TEXT, ts TEXT, status TEXT)')
            conn.execute('DELETE FROM blocked_ips WHERE ip LIKE ?', (f'%{ip}%',))
            conn.commit()
            conn.close()
            logger.info(f"Removed {ip} from SQLite database")
    except Exception as e:
        logger.error(f"Failed to remove from database: {e}")

    # 3. Remove from Redis
    try:
        redis = Redis()
        redis.srem('blocked_ips', ip)
        logger.info(f"Removed {ip} from Redis blocked_ips set")
    except Exception as e:
        logger.error(f"Failed to remove from Redis: {e}")

if __name__ == '__main__':
    target_ip = '192.168.31.16'
    unblock_ip(target_ip)
    print(f'Unblock operations completed for {target_ip}')