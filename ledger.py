from flask import Flask
from extensions import init_extensions, socketio
from models import db
from routes.home import home_bp
from routes.auth import auth_bp
from routes.transactions import transactions_bp
from routes.statements import statements_bp
from routes.settings import settings_bp

def create_app():
    app = Flask(__name__)
    
    # Configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ledger.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'your_secret_key_here'
    
    # Email Configuration
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'input gmail here'
    app.config['MAIL_PASSWORD'] = 'create gmail app password and enter here'
    app.config['SECURITY_PASSWORD_SALT'] = 'unique salt here'
    
    # Initialize extensions
    db.init_app(app)
    init_extensions(app)  # Make sure this is called here
    
    # Register blueprints
    app.register_blueprint(home_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(transactions_bp)
    app.register_blueprint(statements_bp)
    app.register_blueprint(settings_bp)
    
    return app

app = create_app()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True, host="0.0.0.0")
