import sqlite3

# Check database schema
conn = sqlite3.connect('secureguard.db')
cursor = conn.cursor()

# Get all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()
print("Tables:", [row[0] for row in tables])

# Check blocked_ips table schema
cursor.execute("PRAGMA table_info(blocked_ips)")
columns = cursor.fetchall()
print("blocked_ips columns:", [col[1] for col in columns])

conn.close()
