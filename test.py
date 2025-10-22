from flask import Flask, render_template
app = Flask(__name__)

@app.route('/')
def home():
    return render_template('dashboard.html',
        packet_count=0,
        max_packets=2000000,
        blocked_count=0,
        recent_blocks=[],
        protection_status={
            "Firewall": "Testing",
            "Redis": "Active",
            "System": "Protected"
        }
    )

if __name__ == '__main__':
    # Only start the dev server explicitly for local testing when SECUREGUARD_DEV=1
    import os
    if os.environ.get('SECUREGUARD_DEV', '0') == '1':
        app.run(debug=True, host='0.0.0.0', port=5000)