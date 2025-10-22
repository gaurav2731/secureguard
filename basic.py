from flask import Flask, render_template_string

# Initialize Flask
app = Flask(__name__)

# Basic template
template = """
<!DOCTYPE html>
<html>
<head>
    <title>SecureGuard Basic</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 40px;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background: #f5f5f5;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1 { color: #2c3e50; }
        .stats { 
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
            margin-top: 20px;
        }
        .stat-card {
            background: white;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 SecureGuard Basic Dashboard</h1>
        <div class="stats">
            <div class="stat-card">
                <h3>System Status</h3>
                <p>Status: Active</p>
                <p>Protection: Enabled</p>
            </div>
            <div class="stat-card">
                <h3>Security Overview</h3>
                <p>Firewall: Running</p>
                <p>Database: Connected</p>
            </div>
        </div>
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(template)

if __name__ == '__main__':
    import os
    if os.environ.get('SECUREGUARD_DEV', '0') == '1':
        print("Starting server on http://localhost:5000")
        app.run(debug=True, host='127.0.0.1', port=5000)