import json
from bson.json_util import dumps


#Handle ObjectId with Flask
def parse_json(data):
    return json.loads(dumps(data))