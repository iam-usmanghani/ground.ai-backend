from flask import Flask
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from Auth.auth import auth_bp
from Models.models import db
from Config.config import configurations
from flask_cors import CORS
import os
from flask_cors import CORS
def create_app():
    app = Flask(__name__)

    env = os.getenv('FLASK_ENV', 'development')
    app.config.from_object(configurations[env])

    db.init_app(app)
    Bcrypt(app)
    JWTManager(app)

    app.register_blueprint(auth_bp)

    with app.app_context():
        db.create_all()

    return app

if __name__ == '__main__':
    app = create_app()
    # app.run()
    app.run(host='0.0.0.0', port=5000, debug=False)
