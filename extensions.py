from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_socketio import SocketIO
from itsdangerous import URLSafeTimedSerializer

# Initialize extensions
db = SQLAlchemy()
mail = Mail()
socketio = SocketIO()
serializer = URLSafeTimedSerializer('temporary_secret_key')

def init_extensions(app):
    global serializer
    mail.init_app(app)
    socketio.init_app(app, 
                    async_mode='eventlet', 
                    cors_allowed_origins="*",
                    manage_session=False)  
    
    # Re-initialize serializer with the app's secret key and salt
    serializer = URLSafeTimedSerializer(
        secret_key=app.config['SECRET_KEY'],
        salt=app.config['SECURITY_PASSWORD_SALT']
    )

    # Add connection handler
    @socketio.on('connect')
    def handle_connect():
        from flask import session
        from flask_socketio import join_room
        if 'user_id' in session:
            user_id = session['user_id']
            join_room(str(user_id))
            print(f"User {user_id} connected to room")

    # Add authentication handler
    @socketio.on('authenticate')
    def handle_authentication(data):
        from flask import session
        from flask_socketio import join_room
        user_id = data.get('token')
        if user_id and user_id == session.get('user_id'):
            join_room(str(user_id))
            socketio.emit('auth_success', {'status': 'authenticated'}, room=str(user_id))
            print(f"User {user_id} authenticated and joined room")
