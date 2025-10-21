"""
Jinja2 template filters for SecureGuard
"""
from datetime import datetime

def init_filters(app):
    """Initialize all template filters"""
    
    @app.template_filter('datetime')
    def format_datetime(value, format="%Y-%m-%d %H:%M:%S"):
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value)
            except ValueError:
                return value
        if isinstance(value, (int, float)):
            value = datetime.fromtimestamp(value)
        if isinstance(value, datetime):
            return value.strftime(format)
        return value