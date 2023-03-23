from flask import Blueprint

from main import db
from utils.parse_json import parse_json

app_device = Blueprint('app_device', __name__)
