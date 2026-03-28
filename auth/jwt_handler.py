"""
JWT Authentication Handler
============================
Token creation, validation, and refresh using flask-jwt-extended.
"""

from datetime import timedelta
from flask_jwt_extended import JWTManager

jwt = JWTManager()


def init_jwt(app):
    """Initialize JWT with app configuration"""
    app.config['JWT_SECRET_KEY'] = app.config.get('JWT_SECRET_KEY', 'androblight-super-secret-key-change-in-production')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
    app.config['JWT_TOKEN_LOCATION'] = ['headers']
    app.config['JWT_HEADER_NAME'] = 'Authorization'
    app.config['JWT_HEADER_TYPE'] = 'Bearer'

    jwt.init_app(app)

    # Custom error handlers for JWT
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return {
            'status': 'error',
            'error': 'Token has expired',
            'code': 'token_expired'
        }, 401

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return {
            'status': 'error',
            'error': 'Invalid token',
            'code': 'token_invalid'
        }, 401

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return {
            'status': 'error',
            'error': 'Authorization token is missing',
            'code': 'token_missing'
        }, 401

    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return {
            'status': 'error',
            'error': 'Token has been revoked',
            'code': 'token_revoked'
        }, 401
