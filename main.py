import os
import datetime
from flask import Flask, jsonify, abort, request
from flask_cors import CORS
from pymongo import MongoClient
from utils.parse_json import parse_json
import numpy as np
import math

app = Flask(__name__)

#app.register_blueprint(app_device)

#Implementado para resolver problemas de CORS entre o backend e o frontend
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

client = MongoClient()
db = client.iotPlatformDB

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404


#Get all devices registered to the system
@app.route('/devices', methods=['GET'])
def get_devices():
    try:
        devices = db.devices.find()
        return parse_json(devices)
    except:
        return [], 404

#Get specific device by pid
@app.route('/devices/<string:device_pid>', methods=['GET'])
def get_device(device_pid):
    try:
        device = db.devices.find_one({"pid": device_pid})
        return parse_json(device), 200
    except:
        return {}, 404

#Get al sensors from specific device by pid
@app.route('/devices/<string:device_pid>/sensors', methods=['GET'])
def get_device_sensors(device_pid):
    try:
        device_sensors = db.devices.find_one({"pid": device_pid})["sensors"]
        return parse_json(device_sensors), 200
    except:
        return [], 404

#Get all sensors
@app.route('/sensors', methods=['GET'])
def get_sensors():
    try:
        sensors = db.devices.find({}, {"_id": 0, "pid": 1, "sensors": 1})
        return parse_json(sensors)
    except:
        return [], 404

#Get specific sensor by pid
@app.route('/sensors/<string:sensor_pid>', methods=['GET'])
def get_sensor(sensor_pid):
    try:
        sensors = db.devices.find_one({"sensors.pid": sensor_pid}, {"_id": 0, "sensors": 1})
        sensor = [sensor for sensor in sensors["sensors"] if sensor["pid"] == sensor_pid]
        return parse_json(sensor[0]), 200
    except:
        return {}, 404

#Get all readings from a specific device by pid
@app.route('/devices/<string:device_pid>/readings', methods=['GET'])
def get_device_readings(device_pid):
    try:
        readings = db.sensors_readings.find({"device_pid": device_pid})
        return parse_json(readings), 200
    except:
        return [], 404

#Get all readings from a specific sensor by pid
@app.route('/sensors/<string:sensor_pid>/readings', methods=['GET'])
def get_sensor_readings(sensor_pid):
    try:
        readings = db.sensors_readings.find({"sensor_pid": sensor_pid})
        return parse_json(readings), 200
    except:
        return [], 404

#Get all readings
@app.route('/readings', methods=['GET'])
def get_all_readings():
    try:
        limit = request.args.get('limit', default=None, type=int)
        sort = request.args.get('sort', default=None, type=int)

        if limit is not None and (sort==1 or sort==-1):
            readings = db.sensors_readings.find().sort([("timestamp", sort)]).limit(limit)
        elif limit is not None and sort is None:
            readings = db.sensors_readings.find().limit(limit)
        elif limit is None and (sort==1 or sort==-1):
            readings = db.sensors_readings.find().sort([("timestamp", sort)])
        else:
            readings = db.sensors_readings.find()

        return parse_json(readings), 200
    except:
        return [], 404

#Get latest reading from each sensor
@app.route('/readings/latest', methods=['GET'])
def get_latest_readings():
    try:
        devices_sensors = parse_json(db.devices.find({}, {"_id": 0, "pid": 1, "sensors": 1}))
        latest_readings = []
        for device in devices_sensors:
            for sensor in device["sensors"]:
                reading = parse_json(db.sensors_readings.find({"sensor_pid": sensor["pid"]}).sort([("timestamp", -1)]).limit(1))
                if len(reading) > 0:
                    latest_readings.append(reading[0])
        return latest_readings, 200
    except:
        return [], 404

#Get all users
@app.route('/users', methods=['GET'])
def get_users():
    try:
        users = db.users.find()
        return parse_json(users)
    except:
        return [], 404

#Get specific user by username
@app.route('/users/<string:username>', methods=['GET'])
def get_user(username):
    try:
        user = db.users.find_one({"username": username})
        #Porque é necessário fazer esta verifição neste caso?!?!?
        if(user is not None):
            return parse_json(user), 200
        else:
            return {}, 404
    except:
        return {}, 404

#Get all users associated with a specific device
@app.route('/devices/<string:device_pid>/users/', methods=['GET'])
def get_device_users(device_pid):
    try:
        user_devices = parse_json(db.users.find({"devices": device_pid}))
        return user_devices, 200
    except:
        return [], 404

#Get all user devices
@app.route('/users/<string:username>/devices', methods=['GET'])
def get_user_devices(username):
    try:
        user_devices = parse_json(db.users.find_one({"username": username}, {"_id": 0, "devices": 1}))
        if (user_devices is not None):
            return user_devices
        else:
            return [], 404
    except:
        return [], 404

#Update status of an specific device by pid
@app.route('/devices/<string:device_pid>/status', methods=['PUT'])
def update_device_status(device_pid):
    if not request.json or 'status' not in request.json:
        abort(400)  # 400 Bad Request

    try:
        device = parse_json(db.devices.find_one({"pid": device_pid}))

        device["status"] = request.json.get('status', device['status'])

        db.devices.update_one({"pid": device_pid}, {"$set": {"status": device["status"]}})

        return parse_json(device), 200

    except:
        return {}, 404

#Update status of an specific sensor by pid
@app.route('/devices/<string:device_pid>/sensors/<string:sensor_pid>/status', methods=['PUT'])
def update_sensor_status(device_pid, sensor_pid):
    if not request.json or 'status' not in request.json:
        abort(400)  # 400 Bad Request

    try:
        device = parse_json(db.devices.find_one({"pid": device_pid}))
        sensor = [sensor for sensor in device["sensors"] if sensor["pid"] == sensor_pid]

        index_position = device["sensors"].index(sensor[0])

        device["sensors"][index_position]["status"] = request.json.get('status', device["sensors"][index_position]['status'])

        db.devices.update_one({"pid": device_pid}, {"$set": {"sensors."+str(index_position)+".status": device["sensors"][index_position]["status"]}})

        return parse_json(device), 200

    except:
        return {}, 404

#Update calibration of an specific sensor by pid
@app.route('/devices/<string:device_pid>/sensors/<string:sensor_pid>/calibrate', methods=['PUT'])
def calibrate_sensor(device_pid, sensor_pid):
    if not request.json or 'calibrate' not in request.json:
        abort(400)  # 400 Bad Request

    try:
        device = parse_json(db.devices.find_one({"pid": device_pid}))
        sensor = [sensor for sensor in device["sensors"] if sensor["pid"] == sensor_pid]

        index_position = device["sensors"].index(sensor[0])

        device["sensors"][index_position]["calibrate"] = request.json.get('calibrate', device["sensors"][index_position]['calibrate'])

        db.devices.update_one({"pid": device_pid}, {"$set": {"sensors."+str(index_position)+".calibrate": device["sensors"][index_position]["calibrate"]}})

        return parse_json(device), 200

    except:
        return {}, 404

#Update configuration of an specific sensor by pid
@app.route('/devices/<string:device_pid>/sensors/<string:sensor_pid>/config', methods=['PUT'])
def configure_sensor(device_pid, sensor_pid):
    if not request.json or 'config' not in request.json:
        abort(400)  # 400 Bad Request

    try:
        device = parse_json(db.devices.find_one({"pid": device_pid}))
        sensor = [sensor for sensor in device["sensors"] if sensor["pid"] == sensor_pid]

        index_position = device["sensors"].index(sensor[0])

        device["sensors"][index_position]["config"] = request.json.get('config', device["sensors"][index_position]['config'])

        db.devices.update_one({"pid": device_pid}, {"$set": {"sensors."+str(index_position)+".config": device["sensors"][index_position]["config"]}})

        return parse_json(device), 200

    except:
        return {}, 404

#Get all alerts
@app.route('/alerts', methods=['GET'])
def get_all_alerts():
    try:
        limit = request.args.get('limit', default=None, type=int)
        sort = request.args.get('sort', default=None, type=int)

        if limit is not None and (sort == 1 or sort == -1):
            alerts = db.sensor_alerts.find().sort([("timestamp", sort)]).limit(limit)
        elif limit is not None and sort is None:
            alerts = db.sensor_alerts.find().limit(limit)
        elif limit is None and (sort == 1 or sort == -1):
            alerts = db.sensor_alerts.find().sort([("timestamp", sort)])
        else:
            alerts = db.sensor_alerts.find()

        return parse_json(alerts), 200
    except:
        return [], 404

#Get all logs
@app.route('/logs', methods=['GET'])
def get_all_logs():
    try:
        limit = request.args.get('limit', default=None, type=int)
        sort = request.args.get('sort', default=None, type=int)

        if limit is not None and (sort == 1 or sort == -1):
            logs = db.logs.find().sort([("timestamp", sort)]).limit(limit)
        elif limit is not None and sort is None:
            logs = db.logs.find().limit(limit)
        elif limit is None and (sort == 1 or sort == -1):
            logs = db.logs.find().sort([("timestamp", sort)])
        else:
            logs = db.logs.find()

        return parse_json(logs), 200
    except:
        return [], 404

#Register device
@app.route('/devices/register', methods=['POST'])
def register_device():
    if not request.json or 'pid' not in request.json or 'name' not in request.json or 'description' not in request.json or 'location' not in request.json\
    or 'name' not in request.json["location"] or 'status' not in request.json or 'sensors' not in request.json:
        abort(400)  # 400 Bad Request

    try:
        new_device = {
            'pid': request.json['pid'],
            'name': request.json['name'],
            'description': request.json['description'],
            'location': request.json['location'],
            'status': request.json['status'],
            'sensors': request.json['sensors']
        }

        db.devices.insert_one(parse_json(new_device))

        return jsonify(new_device), 200

    except:
        return {}, 404

#Delete device by pid
@app.route('/devices/<string:device_pid>', methods=['DELETE'])
def delete_device(device_pid):
    try:
        device = db.devices.find_one({"pid": device_pid})
        db.devices.delete_one({"pid": device_pid})

        return parse_json(device), 200

    except:
        return {}, 404

#Add reading
@app.route('/readings', methods=['POST'])
def add_reading():
    if not request.json or 'device_pid' not in request.json or 'sensor_pid' not in request.json or 'value' not in request.json:
        abort(400)  # 400 Bad Request

    try:
        new_reading = {
            'device_pid': request.json['device_pid'],
            'sensor_pid': request.json['sensor_pid'],
            'value': request.json['value'],
            'timestamp': request.json.get('timestamp', datetime.datetime.utcnow())
        }

        db.sensors_readings.insert_one(parse_json(new_reading))

        return jsonify(new_reading), 200

    except:
        return {}, 404

#Register user
@app.route('/users/register', methods=['POST'])
def register_user():
    if not request.json or 'username' not in request.json or 'name' not in request.json or 'email' not in request.json:
        abort(400)  # 400 Bad Request

    try:
        new_user = {
            'username': request.json['username'],
            'name': request.json['name'],
            'email': request.json['email'],
            'devices': request.json.get('devices', [])
        }

        db.users.insert_one(parse_json(new_user))

        return jsonify(new_user), 200

    except:
        return {}, 404

#Delete user by username
@app.route('/users/<string:username>', methods=['DELETE'])
def delete_user(username):
    try:
        user = db.users.find_one({"username": username})
        db.users.delete_one({"username": username})

        return parse_json(user), 200

    except:
        return {}, 404

#Update information of an specific user by username
@app.route('/users/<string:username>', methods=['PUT'])
def update_user_info(username):
    if not request.json:
        abort(400)  # 400 Bad Request

    try:
        user = parse_json(db.users.find_one({"username": username}))

        new_user_info = {
            "username": request.json.get('username', user['username']),
            "name": request.json.get('name', user['name']),
            "email": request.json.get('email', user['email']),
            "devices": request.json.get('devices', user['devices'])
        }

        db.users.update_one({"username": username}, {"$set": new_user_info})

        return parse_json(new_user_info), 200

    except:
        return {}, 404

#Update devices from user
@app.route('/devices/<string:device_pid>/users/<string:username>', methods=['POST'])
def update_user_devices(device_pid, username):
    try:
        user = parse_json(db.users.find_one({"username": username}))

        #Verifica se o device existe na lista
        if device_pid in user["devices"]:
            user["devices"].remove(device_pid)
        else:
            user["devices"].append(device_pid)

        db.users.update_one({"username": username}, {"$set": {"devices": user["devices"]}})

        return user, 200

    except:
        return {}, 404

#Get latest reading from specific sensor and device
@app.route('/devices/<string:device_pid>/sensors/<string:sensor_pid>/readings/latest', methods=['GET'])
def get_device_sensor_latest_reading(device_pid, sensor_pid):
    try:
        latest_reading = parse_json(db.sensors_readings.find({"device_pid": device_pid, "sensor_pid": sensor_pid}).sort([("timestamp", -1)]).limit(1))

        return latest_reading[0], 200
    except:
        return [], 404

#Add new alert
@app.route('/alerts', methods=['POST'])
def add_alert():
    if not request.json or 'device_pid' not in request.json or 'sensor_pid' not in request.json or 'value' not in request.json or 'type' not in request.json \
            or 'description' not in request.json:
        abort(400)  # 400 Bad Request

    try:
        new_alert = {
            'device_pid': request.json['device_pid'],
            'sensor_pid': request.json['sensor_pid'],
            'value': request.json['value'],
            'type': request.json['type'],
            'description': request.json['description'],
            'cleared': request.json.get('cleared', 0),
            'timestamp': request.json.get('timestamp', datetime.datetime.utcnow())
        }

        db.sensor_alerts.insert_one(parse_json(new_alert))

        return jsonify(new_alert), 200

    except:
        return {}, 404

#Add new log
@app.route('/logs', methods=['POST'])
def add_log():
    if not request.json or 'device_pid' not in request.json or 'description' not in request.json:
        abort(400)  # 400 Bad Request

    try:
        new_log = {
            'device_pid': request.json['device_pid'],
            'description': request.json['description'],
            'timestamp': request.json.get('timestamp', datetime.datetime.utcnow())
        }

        if 'sensor_pid' in request.json:
            new_log["sensor_pid"] = request.json['sensor_pid']

        db.logs.insert_one(parse_json(new_log))

        return jsonify(new_log), 200

    except:
        return {}, 404

#Get logs of an specific device by pid
@app.route('/devices/<string:device_pid>/logs', methods=['GET'])
def get_device_logs(device_pid):
    try:
        log = db.logs.find({"device_pid": device_pid})

        return parse_json(log), 200

    except:
        return [], 404

#Get logs of an specific sensor by pid
@app.route('/devices/<string:device_pid>/sensors/<string:sensor_pid>/logs', methods=['GET'])
def get_sensor_logs(device_pid, sensor_pid):
    try:
        log = db.logs.find({"device_pid": device_pid, "sensor_pid": sensor_pid})

        return parse_json(log), 200

    except:
        return [], 404

#Get average of readings from specific sensor
@app.route('/devices/<string:device_pid>/sensors/<string:sensor_pid>/readings/average', methods=['GET'])
def get_sensor_average_readings(device_pid, sensor_pid):
    try:
        #Lista de objetos com a propriedade value
        readings = parse_json(db.sensors_readings.find({"device_pid": device_pid, "sensor_pid": sensor_pid}, {"_id": 0, "value": 1}))
        #Lista dos valores que estavam dentro da propriedade
        filtered_readings = [reading["value"] for reading in readings]
        #Média dos valores do array
        average_reading = np.mean(filtered_readings)

        #Se não existem valores, retorna objeto vazio
        if math.isnan(average_reading):
            return {}, 200


        return jsonify({"average": average_reading}), 200
    except:
        return {}, 404

#Get max reading from specific sensor
@app.route('/devices/<string:device_pid>/sensors/<string:sensor_pid>/readings/max', methods=['GET'])
def get_sensor_max_reading(device_pid, sensor_pid):
    try:
        #Lista de objetos com a propriedade value
        readings = parse_json(db.sensors_readings.find({"device_pid": device_pid, "sensor_pid": sensor_pid}, {"_id": 0, "value": 1}))
        #Lista dos valores que estavam dentro da propriedade
        filtered_readings = [reading["value"] for reading in readings]
        #Média dos valores do array
        max_reading = np.max(filtered_readings)

        #Se não existem valores, retorna objeto vazio
        if math.isnan(max_reading):
            return {}, 200


        return jsonify({"max": max_reading}), 200
    except:
        return {}, 404

#Get min reading from specific sensor
@app.route('/devices/<string:device_pid>/sensors/<string:sensor_pid>/readings/min', methods=['GET'])
def get_sensor_min_reading(device_pid, sensor_pid):
    try:
        #Lista de objetos com a propriedade value
        readings = parse_json(db.sensors_readings.find({"device_pid": device_pid, "sensor_pid": sensor_pid}, {"_id": 0, "value": 1}))
        #Lista dos valores que estavam dentro da propriedade
        filtered_readings = [reading["value"] for reading in readings]
        #Média dos valores do array
        min_reading = np.min(filtered_readings)

        #Se não existem valores, retorna objeto vazio
        if math.isnan(min_reading):
            return {}, 200


        return jsonify({"min": min_reading}), 200
    except:
        return {}, 404

#Get sum of readings from specific sensor
@app.route('/devices/<string:device_pid>/sensors/<string:sensor_pid>/readings/sum', methods=['GET'])
def get_sensor_sum_readings(device_pid, sensor_pid):
    try:
        #Lista de objetos com a propriedade value
        readings = parse_json(db.sensors_readings.find({"device_pid": device_pid, "sensor_pid": sensor_pid}, {"_id": 0, "value": 1}))
        #Lista dos valores que estavam dentro da propriedade
        filtered_readings = [reading["value"] for reading in readings]
        #Média dos valores do array
        sum_readings = np.sum(filtered_readings)

        #Se não existem valores, retorna objeto vazio
        if math.isnan(sum_readings):
            return {}, 200


        return jsonify({"sum": sum_readings}), 200
    except:
        return {}, 404

#Get count of readings from specific sensor
@app.route('/devices/<string:device_pid>/sensors/<string:sensor_pid>/readings/count', methods=['GET'])
def get_sensor_count_readings(device_pid, sensor_pid):
    try:
        #Lista de objetos com a propriedade value
        readings = parse_json(db.sensors_readings.find({"device_pid": device_pid, "sensor_pid": sensor_pid}, {"_id": 0, "value": 1}))
        #Lista dos valores que estavam dentro da propriedade
        filtered_readings = [reading["value"] for reading in readings]
        #Média dos valores do array
        count_readings = len(filtered_readings)

        return jsonify({"count": count_readings}), 200
    except:
        return {}, 404

#Get average of readings from specific device
@app.route('/devices/<string:device_pid>/readings/average', methods=['GET'])
def get_device_average_readings(device_pid):
    try:
        #Lista de objetos com a propriedade value
        readings = parse_json(db.sensors_readings.find({"device_pid": device_pid}, {"_id": 0, "value": 1}))
        #Lista dos valores que estavam dentro da propriedade
        filtered_readings = [reading["value"] for reading in readings]
        #Média dos valores do array
        average_reading = np.mean(filtered_readings)

        #Se não existem valores, retorna objeto vazio
        if math.isnan(average_reading):
            return {}, 200


        return jsonify({"average": average_reading}), 200
    except:
        return {}, 404

#Get max reading from specific device
@app.route('/devices/<string:device_pid>/readings/max', methods=['GET'])
def get_device_max_reading(device_pid):
    try:
        #Lista de objetos com a propriedade value
        readings = parse_json(db.sensors_readings.find({"device_pid": device_pid}, {"_id": 0, "value": 1}))
        #Lista dos valores que estavam dentro da propriedade
        filtered_readings = [reading["value"] for reading in readings]
        #Máximo dos valores do array
        max_reading = np.max(filtered_readings)

        #Se não existem valores, retorna objeto vazio
        if math.isnan(max_reading):
            return {}, 200


        return jsonify({"max": max_reading}), 200
    except:
        return {}, 404

#Get min reading from specific device
@app.route('/devices/<string:device_pid>/readings/min', methods=['GET'])
def get_device_min_reading(device_pid):
    try:
        #Lista de objetos com a propriedade value
        readings = parse_json(db.sensors_readings.find({"device_pid": device_pid}, {"_id": 0, "value": 1}))
        #Lista dos valores que estavam dentro da propriedade
        filtered_readings = [reading["value"] for reading in readings]
        #Mínimo dos valores do array
        min_reading = np.min(filtered_readings)

        #Se não existem valores, retorna objeto vazio
        if math.isnan(min_reading):
            return {}, 200


        return jsonify({"min": min_reading}), 200
    except:
        return {}, 404

#Get sum of readings from specific device
@app.route('/devices/<string:device_pid>/readings/sum', methods=['GET'])
def get_device_sum_readings(device_pid):
    try:
        #Lista de objetos com a propriedade value
        readings = parse_json(db.sensors_readings.find({"device_pid": device_pid}, {"_id": 0, "value": 1}))
        #Lista dos valores que estavam dentro da propriedade
        filtered_readings = [reading["value"] for reading in readings]
        #Soma dos valores do array
        sum_readings = np.sum(filtered_readings)

        #Se não existem valores, retorna objeto vazio
        if math.isnan(sum_readings):
            return {}, 200


        return jsonify({"sum": sum_readings}), 200
    except:
        return {}, 404

#Get count of readings from specific device
@app.route('/devices/<string:device_pid>/readings/count', methods=['GET'])
def get_device_count_readings(device_pid):
    try:
        #Lista de objetos com a propriedade value
        readings = parse_json(db.sensors_readings.find({"device_pid": device_pid}, {"_id": 0, "value": 1}))
        #Lista dos valores que estavam dentro da propriedade
        filtered_readings = [reading["value"] for reading in readings]
        #Contador dos valores do array
        count_readings = len(filtered_readings)

        return jsonify({"count": count_readings}), 200
    except:
        return {}, 404

#Get status of an specific device by pid
@app.route('/devices/<string:device_pid>/status/check', methods=['GET'])
def get_device_status(device_pid):
    try:
        device = parse_json(db.devices.find_one({"pid": device_pid}, {"_id": 0, "status": 1}))

        return parse_json(device), 200

    except:
        return {}, 404

#Get status of an specific sensor by pid
@app.route('/devices/<string:device_pid>/sensors/<string:sensor_pid>/status/check', methods=['GET'])
def get_sensor_status(device_pid, sensor_pid):
    try:
        device = parse_json(db.devices.find_one({"pid": device_pid}))
        sensor = [sensor for sensor in device["sensors"] if sensor["pid"] == sensor_pid]

        index_position = device["sensors"].index(sensor[0])

        sensor_status = device["sensors"][index_position]["status"]

        return parse_json({"status": sensor_status}), 200

    except:
        return {}, 404

#Get configurations of an specific sensor by pid
@app.route('/devices/<string:device_pid>/sensors/<string:sensor_pid>/config/check', methods=['GET'])
def get_sensor_config(device_pid, sensor_pid):
    try:
        device = parse_json(db.devices.find_one({"pid": device_pid}))
        sensor = [sensor for sensor in device["sensors"] if sensor["pid"] == sensor_pid]

        index_position = device["sensors"].index(sensor[0])

        sensor_config = device["sensors"][index_position]["config"]

        return parse_json({"config": sensor_config}), 200

    except:
        return {}, 404

#Reset configuration of an specific sensor by pid
@app.route('/devices/<string:device_pid>/sensors/<string:sensor_pid>/config/reset', methods=['PUT'])
def reset_sensor_config(device_pid, sensor_pid):
    try:
        device = parse_json(db.devices.find_one({"pid": device_pid}))
        sensor = [sensor for sensor in device["sensors"] if sensor["pid"] == sensor_pid]

        index_position = device["sensors"].index(sensor[0])

        device["sensors"][index_position]["config"] = ""

        db.devices.update_one({"pid": device_pid}, {"$set": {"sensors."+str(index_position)+".config": device["sensors"][index_position]["config"]}})

        return parse_json(device), 200

    except:
        return {}, 404

#Get calibration of an specific sensor by pid
@app.route('/devices/<string:device_pid>/sensors/<string:sensor_pid>/calibrate/check', methods=['GET'])
def get_sensor_calibration(device_pid, sensor_pid):
    try:
        device = parse_json(db.devices.find_one({"pid": device_pid}))
        sensor = [sensor for sensor in device["sensors"] if sensor["pid"] == sensor_pid]

        index_position = device["sensors"].index(sensor[0])

        sensor_calibration = device["sensors"][index_position]["calibrate"]

        return parse_json({"config": sensor_calibration}), 200

    except:
        return {}, 404

#Get information of aggregate readings from specific sensor and device
@app.route('/devices/<string:device_pid>/sensors/<string:sensor_pid>/data/aggregate', methods=['GET'])
def get_device_sensor_aggregate_data(device_pid, sensor_pid):
    try:
        #Lista de objetos com a propriedade value
        readings = parse_json(db.sensors_readings.find({"device_pid": device_pid, "sensor_pid": sensor_pid}, {"_id": 0, "value": 1}))
        #Lista dos valores que estavam dentro da propriedade
        filtered_readings = [reading["value"] for reading in readings]
        #Média dos valores do array
        average_reading = np.mean(filtered_readings)
        max_reading = np.max(filtered_readings, initial=0)
        min_reading = np.min(filtered_readings, initial=0)
        sum_readings = np.sum(filtered_readings)
        count_readings = len(filtered_readings)

        #Se não existem valores, retorna objeto vazio
        if math.isnan(average_reading):
            average_reading = 0
        if math.isnan(max_reading):
            max_reading = 0
        if math.isnan(min_reading):
            min_reading = 0
        if math.isnan(sum_readings):
            sum_readings = 0

        return jsonify({"average": average_reading, "max": max_reading, "min": min_reading, "sum": sum_readings, "count": count_readings}), 200
    except:
        return {}, 404


#Get number of device (and number of sensors), alerts, logs... documents in systems
@app.route('/system/count_documents', methods=['GET'])
def system_count_documents():
    try:
        #Num Devices in System
        devices = parse_json(db.devices.find())
        num_devices = len(devices)

        #Num Sensors in System
        sensors = []
        for device in devices:
            for sensor in device["sensors"]:
                if sensor["pid"] not in sensors:
                    sensors.append(sensor["pid"])
        num_sensors = len(sensors)

        #Num Readings in System
        num_readings = db.sensors_readings.count_documents({})

        #Num Logs in System
        num_logs = db.logs.count_documents({})

        #Num Alerts in System
        num_alerts = db.sensor_alerts.count_documents({})
        num_alerts_cleared = db.sensor_alerts.count_documents({"cleared": 1})

        return jsonify({"devices": num_devices, "sensors": num_sensors, "readings": num_readings, "logs": num_logs, "alerts": {"total": num_alerts, "total_cleared": num_alerts_cleared}}), 200
    except:
        return {}, 404

#Get statistics about data of an specific sensor
@app.route('/devices/<string:device_pid>/sensors/<string:sensor_pid>/data/statistics', methods=['GET'])
def get_device_sensor_statistics_data(device_pid, sensor_pid):
    try:
        readings = parse_json(db.sensors_readings.find({"device_pid": device_pid, "sensor_pid": sensor_pid}, {"_id": 0, "value": 1}))
        filtered_readings = [reading["value"] for reading in readings]

        #Média dos valores do array
        average_reading = np.mean(filtered_readings)

        #Máximo dos valores do array
        max_reading = np.max(filtered_readings, initial=0)

        #Mínimo dos valores do array
        min_reading = np.min(filtered_readings, initial=0)

        # Soma dos valores do array
        sum_readings = np.sum(filtered_readings)

        # Contador dos valores do array
        count_readings = len(filtered_readings)

        return jsonify({"average": average_reading, "max": max_reading, "min": min_reading, "sum": sum_readings, "count": count_readings}), 200
    except:
        return {}, 404

#Get statistics about data of an specific device
@app.route('/devices/<string:device_pid>/data/statistics', methods=['GET'])
def get_device_statistics_data(device_pid):
    try:
        readings = parse_json(db.sensors_readings.find({"device_pid": device_pid}, {"_id": 0, "value": 1}))
        filtered_readings = [reading["value"] for reading in readings]

        #Média dos valores do array
        average_reading = np.mean(filtered_readings)

        #Máximo dos valores do array
        max_reading = np.max(filtered_readings, initial=0)

        #Mínimo dos valores do array
        min_reading = np.min(filtered_readings, initial=0)

        # Soma dos valores do array
        sum_readings = np.sum(filtered_readings)

        # Contador dos valores do array
        count_readings = len(filtered_readings)

        return jsonify({"average": average_reading, "max": max_reading, "min": min_reading, "sum": sum_readings, "count": count_readings}), 200
    except:
        return {}, 404

#Get all alerts from device
@app.route('/devices/<string:device_pid>/alerts', methods=['GET'])
def get_device_alerts(device_pid):
    try:
        limit = request.args.get('limit', default=None, type=int)
        sort = request.args.get('sort', default=None, type=int)

        if limit is not None and (sort == 1 or sort == -1):
            alerts = db.sensor_alerts.find({"device_pid": device_pid}).sort([("timestamp", sort)]).limit(limit)
        elif limit is not None and sort is None:
            alerts = db.sensor_alerts.find({"device_pid": device_pid}).limit(limit)
        elif limit is None and (sort == 1 or sort == -1):
            alerts = db.sensor_alerts.find({"device_pid": device_pid}).sort([("timestamp", sort)])
        else:
            alerts = db.sensor_alerts.find({"device_pid": device_pid})

        return parse_json(alerts), 200
    except:
        return [], 404

#Get all alerts from device
@app.route('/devices/<string:device_pid>/sensors/<string:sensor_pid>/alerts', methods=['GET'])
def get_sensor_alerts(device_pid, sensor_pid):
    try:
        limit = request.args.get('limit', default=None, type=int)
        sort = request.args.get('sort', default=None, type=int)

        if limit is not None and (sort == 1 or sort == -1):
            alerts = db.sensor_alerts.find({"device_pid": device_pid, "sensor_pid": sensor_pid}).sort([("timestamp", sort)]).limit(limit)
        elif limit is not None and sort is None:
            alerts = db.sensor_alerts.find({"device_pid": device_pid, "sensor_pid": sensor_pid}).limit(limit)
        elif limit is None and (sort == 1 or sort == -1):
            alerts = db.sensor_alerts.find({"device_pid": device_pid, "sensor_pid": sensor_pid}).sort([("timestamp", sort)])
        else:
            alerts = db.sensor_alerts.find({"device_pid": device_pid, "sensor_pid": sensor_pid})

        return parse_json(alerts), 200
    except:
        return [], 404

#Get count of alerts from specific device
@app.route('/devices/<string:device_pid>/alerts/count', methods=['GET'])
def get_device_count_alerts(device_pid):
    try:

        # Num Alerts of Device
        num_alerts = db.sensor_alerts.count_documents({"device_pid": device_pid})
        num_alerts_cleared = db.sensor_alerts.count_documents({"device_pid": device_pid, "cleared": 1})

        return jsonify({"alerts": {"total": num_alerts, "total_cleared": num_alerts_cleared}}), 200
    except:
        return {}, 404

#Get count of alerts from specific sensor
@app.route('/devices/<string:device_pid>/sensors/<string:sensor_pid>/alerts/count', methods=['GET'])
def get_sensor_count_alerts(device_pid, sensor_pid):
    try:

        # Num Alerts of Sensor
        num_alerts = db.sensor_alerts.count_documents({"device_pid": device_pid, "sensor_pid": sensor_pid})
        num_alerts_cleared = db.sensor_alerts.count_documents({"device_pid": device_pid, "sensor_pid": sensor_pid, "cleared": 1})

        return jsonify({"alerts": {"total": num_alerts, "total_cleared": num_alerts_cleared}}), 200
    except:
        return {}, 404

#Get count of logs from specific device
@app.route('/devices/<string:device_pid>/logs/count', methods=['GET'])
def get_device_count_logs(device_pid):
    try:

        # Num Logs of Device
        num_logs = db.logs.count_documents({"device_pid": device_pid})

        return jsonify({"count": num_logs}), 200
    except:
        return {}, 404

#Get count of logs from specific sensor
@app.route('/devices/<string:device_pid>/sensors/<string:sensor_pid>/logs/count', methods=['GET'])
def get_sensor_count_logs(device_pid, sensor_pid):
    try:
        # Num Logs of Sensor
        num_logs = db.logs.count_documents({"device_pid": device_pid, "sensor_pid": sensor_pid})

        return jsonify({"count": num_logs}), 200
    except:
        return {}, 404

#Get number of sensors, readings, alerts, logs... documents of specific device
@app.route('/devices/<string:device_pid>/count_documents', methods=['GET'])
def device_count_documents(device_pid):
    try:
        # Num readings of Device
        readings = parse_json(db.sensors_readings.find({"device_pid": device_pid}, {"_id": 0, "value": 1}))
        filtered_readings = [reading["value"] for reading in readings]
        num_readings = len(filtered_readings)

        # Num Logs of Device
        num_logs = db.logs.count_documents({"device_pid": device_pid})

        # Num Alerts of Device
        num_alerts = db.sensor_alerts.count_documents({"device_pid": device_pid})
        num_alerts_cleared = db.sensor_alerts.count_documents({"device_pid": device_pid, "cleared": 1})

        # Num Sensors of Device
        num_sensors = len(parse_json(db.devices.find_one({"pid": device_pid})["sensors"]))

        return jsonify({"sensors": num_sensors, "readings": num_readings, "logs": num_logs, "alerts": {"total": num_alerts, "total_cleared": num_alerts_cleared}}), 200
    except:
        return {}, 404

#Get number of readings, alerts, logs... documents of specific sensor
@app.route('/devices/<string:device_pid>/sensors/<string:sensor_pid>/count_documents', methods=['GET'])
def sensor_count_documents(device_pid, sensor_pid):
    try:
        # Num readings of Sensor
        readings = parse_json(db.sensors_readings.find({"device_pid": device_pid, "sensor_pid": sensor_pid}, {"_id": 0, "value": 1}))
        filtered_readings = [reading["value"] for reading in readings]
        num_readings = len(filtered_readings)

        # Num Logs of Sensor
        num_logs = db.logs.count_documents({"device_pid": device_pid, "sensor_pid": sensor_pid})

        # Num Alerts of Sensor
        num_alerts = db.sensor_alerts.count_documents({"device_pid": device_pid, "sensor_pid": sensor_pid})
        num_alerts_cleared = db.sensor_alerts.count_documents({"device_pid": device_pid, "sensor_pid": sensor_pid, "cleared": 1})

        return jsonify({"readings": num_readings, "logs": num_logs, "alerts": {"total": num_alerts, "total_cleared": num_alerts_cleared}}), 200
    except:
        return {}, 404


if __name__ == '__main__':
    app.debug = True

    # If you have the debugger disabled or trust the users on your network,
    # you can make the server publicly available simply by adding --host=0.0.0.0
    host = os.environ.get('IP', '127.0.0.1')

    port = int(os.environ.get('PORT', 8080))

    app.run(host=host, port=port)

