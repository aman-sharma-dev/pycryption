from flask import Blueprint

web_ui_bp = Blueprint('web_ui', __name__, template_folder='templates')

from . import routes
