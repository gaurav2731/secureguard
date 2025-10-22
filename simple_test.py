from flask import Flask, render_template_string
app = Flask(__name__)

template = """
<!DOCTYPE html>
<html>
<head>
    <title>SecureGuard Test</title>
</head>
<body>
    <h1>🔐 SecureGuard Test Page</h1>
    <p>If you can see this, the server is working!</p>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(template)

if __name__ == '__main__':
    import os
    if os.environ.get('SECUREGUARD_DEV', '0') == '1':
        app.run(debug=True, host='0.0.0.0', port=5000)