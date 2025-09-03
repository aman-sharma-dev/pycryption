from flask import Flask
from config import config
from .web_ui import web_ui_bp
from . import cli
import os

def create_app(config_name=None):
    if config_name is None:
        config_name = os.environ.get('FLASK_CONFIG', 'default')

    app = Flask(__name__, instance_relative_config=True)

    # Load configuration from config.py
    app.config.from_object(config[config_name])

    # Load configuration from instance/config.py, if it exists
    app.config.from_pyfile('config.py', silent=True)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # Register the web UI blueprint
    app.register_blueprint(web_ui_bp)

    # Initialize the CLI commands
    cli.init_app(app)

    return app
