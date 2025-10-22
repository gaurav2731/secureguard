from redis_connection import redis_conn

print("REDIS_CLIENT_CONNECTED:", bool(redis_conn.client))
blocked = redis_conn.get_blocked_ips()
print("BLOCKED_TYPE:", type(blocked))
try:
    print("BLOCKED_COUNT:", len(blocked))
except Exception as e:
    print("BLOCKED_COUNT: error computing length", e)
try:
    sample = list(blocked)[:10]
except Exception as e:
    sample = f"error listing blocked: {e}"
print("BLOCKED_SAMPLE:", sample)
