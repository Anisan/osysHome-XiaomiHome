""" 
# Xiaomi home zigbee gateway


"""
import time
import json
import threading
import datetime
import socket
import struct
from flask import redirect, render_template, jsonify, request
from sqlalchemy import delete, or_
from app.database import db, session_scope, row2dict, getSession
from app.core.main.BasePlugin import BasePlugin
from app.core.models.Tasks import Task
from plugins.XiaomiHome.models.Device import Device
from plugins.XiaomiHome.models.Command import Command
from app.authentication.handlers import handle_admin_required
from app.core.lib.object import setProperty, callMethod, setLinkToObject, removeLinkFromObject

XIAOMI_MULTICAST_ADDRESS = '224.0.0.50'
XIAOMI_MULTICAST_PORT = 9898

class XiaomiHome(BasePlugin):

    def __init__(self, app):
        super().__init__(app, __name__)
        self.title = "XiaomiHome"
        self.description = """Xiaomi home zigbee gateway"""
        self.system = True
        self.actions = ['cycle','search']
        self.category = "Devices"
        self.version = "0.1"
        self.sock = None
        
        self.latest_data_received = time.time()
        
        import logging
        self.logger.setLevel(logging.DEBUG)

    def initialization(self):
        self.xiaomi_socket_connect()

    def admin(self, request):
        id = request.args.get("device", None)
        op = request.args.get("op", None)
        if op == 'edit':
            return render_template("xiaomi_device.html", id=id)
        
        if op == 'delete':
            with session_scope() as session:
                from sqlalchemy import delete
                sql = delete(Command).where(Command.device_id == int(id))
                session.execute(sql)
                sql = delete(Device).where(Device.id == int(id))
                session.execute(sql)
                session.commit()
                return redirect(self.name)

        devices = Device.query.all()
        return render_template("xiaomi_home.html", devices=devices)

    def route_index(self):

        @self.blueprint.route('/XiaomiHome/device', methods=['POST'])
        @self.blueprint.route('/XiaomiHome/device/<device_id>', methods=['GET', 'POST'])
        @handle_admin_required
        def point_xi_device(device_id=None):
            with session_scope() as session:
                if request.method == "GET":
                    dev = Device.get_by_id(device_id)
                    device = row2dict(dev)
                    device['commands'] = []
                    cmnds = Command.query.filter(Command.device_id == device_id).all()
                    for cmnd in cmnds:
                        device['commands'].append(row2dict(cmnd))
                    return jsonify(device)
                if request.method == "POST":
                    data = request.get_json()
                    if data['id']:
                        device = session.query(Device).where(Device.id == int(data['id'])).one()
                    else:
                        device = Device()
                        session.add(device)
                        session.commit()

                    device.title = data['title']
                    device.gate_key = data['gate_key']

                    for cmd in data['commands']:
                        cmnd_rec = session.query(Command).filter(Command.title == cmd['title']).one()
                        if cmnd_rec.linked_object:
                            removeLinkFromObject(cmnd_rec.linked_object, cmnd_rec.linked_property, self.name)
                        cmnd_rec.linked_object = cmd['linked_object']
                        cmnd_rec.linked_property = cmd['linked_property']
                        cmnd_rec.linked_method = cmd['linked_method']
                        if cmnd_rec.linked_object:
                            setLinkToObject(cmnd_rec.linked_object, cmnd_rec.linked_property, self.name)

                    session.commit()
                    
                    return 'Device updated successfully', 200
        
        @self.blueprint.route('/XiaomiHome/delete_cmnd/<cmd_id>', methods=['GET', 'POST'])
        @handle_admin_required
        def point_xi_delcmd(cmd_id=None):
            with session_scope() as session:
                sql = delete(Command).where(Command.id == int(cmd_id))
                session.execute(sql)
                session.commit()
            
    def search(self, query: str) -> list:
        res = []
        cmnds = Command.query.filter(or_(Command.linked_object.name.contains(query),Command.linked_property.contains(query),Command.linked_method.contains(query))).all()
        for cmd in cmnds:
            res.append({"url":f'XiaomiHome?op=edit&device={cmd.device_id}', "title":f'{cmd.title}', "tags":[{"name":"XiaomiHome","color":"success"}]})
        return res

    def cyclic_task(self):

        if self.sock:
            try:
                buf, (remote_ip, remote_port) = self.sock.recvfrom(1024)
                buf = buf.decode('utf-8')
            except socket.timeout:
                buf = ''
            
            if buf:
                self.processMessage(buf, remote_ip)
                self.latest_data_received = time.time()
            
            if time.time() - self.latest_data_received > 60:
                self.logger.error("Xiaomi data timeout...")
                self.sock.close()
                self.xiaomi_socket_connect()
        else:
            self.event.wait(15.0)
            if not self.event.is_set():
                self.xiaomi_socket_connect()
    
    def xiaomi_socket_connect(self):
        bind_ip = '0.0.0.0'  # Подставь необходимый IP-адрес
        
        # Создание UDP сокета
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        except socket.error as e:
            self.logger.exception("Failed to create socket [%s] %s", e.errno, e.strerror)
            self.sock = None
            return

        self.logger.debug("Socket created")

        # Привязка сокета к IP-адресу
        try:
            self.sock.bind((bind_ip, XIAOMI_MULTICAST_PORT))
        except socket.error as e:
            self.logger.exception("Could not bind socket (Binding IP: %s) [%s] %s", bind_ip, e.errno, e.strerror)
            self.sock = None
            return

        self.logger.debug("Socket bind OK (Binding IP: %s)", bind_ip)

        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.settimeout(1)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)

        group = socket.inet_aton(XIAOMI_MULTICAST_ADDRESS)
        mreq = struct.pack('4sL', group, socket.INADDR_ANY)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        message = '{"cmd":"whois"}'

        self.logger.debug("Sending discovery packet to %s (%s)", XIAOMI_MULTICAST_ADDRESS, message)
        self.sock.sendto(message.encode(), (XIAOMI_MULTICAST_ADDRESS, XIAOMI_MULTICAST_PORT))

    def send_message(self, message, ip):
        self.logger.debug("Sending message (%s) to %s", message, ip)
        self.sock.sendto(json.dumps(message).encode(), (ip, XIAOMI_MULTICAST_PORT))

    def processMessage(self, message, ip):
        with session_scope() as session:
            self.logger.debug("Recv from %s: %s", ip, message)
            
            message_data = json.loads(message)
            if 'data' in message_data:
                data_text = message_data['data'].replace('\\"', '"')
                message_data['data'] = json.loads(data_text)
            
            if 'sid' in message_data:
                device = session.query(Device).filter(Device.sid == message_data['sid']).one_or_none()
                
                if not device:
                    device = Device()
                    device.sid = message_data['sid']
                    device.type = message_data['model']
                    device.title = f"{message_data['model'].capitalize()} {datetime.datetime.now().strftime('%Y-%m-%d')}"
                    session.add(device)
                    session.commit()
                    device_id = device.id

                    commands = []
                    if device.type == 'gateway':
                        commands.append('ringtone')
                    if device.type == 'curtain':
                        commands.append('curtain_status')
                    
                    for command in commands:
                        cmd_rec = session.query(Command).filter(Command.device_id == device_id, Command.title == command).one_or_none()
                        if not cmd_rec:
                            cmd_rec = Command()
                            cmd_rec.device_id = device_id
                            cmd_rec.title = command
                            session.add(cmd_rec)
                            session.commit()
                else:
                    device_id = device.id
                
                if 'token' in message_data and message_data['token']:
                    device.token = message_data['token']
                    device.gate_ip = ip
                    device.updated = datetime.datetime.now()
                else:
                    device.gate_ip = ip
                    device.updated = datetime.datetime.now()
                
                session.commit()

                if 'cmd' in message_data and message_data['cmd']:
                    command = message_data['cmd']
                    got_commands = []
                    data = message_data.get('data', {})
                    
                    if 'ip' in data:
                        got_commands.append({'command': 'ip', 'value': data['ip']})
                    
                    if command in ['write_ack', 'read_ack', 'report']:
                        got_commands.append({'command': command, 'value': json.dumps(message_data)})
                    
                    if command == 'report' and message_data['model'] == 'gateway':
                        if 'rgb' in data:
                            value_str = f"{data['rgb']:08x}"
                            got_commands.append({'command': 'rgb', 'value': value_str[-6:]})
                            got_commands.append({'command': 'brightness', 'value': int(value_str[:2], 16)})
                    
                    if 'lux' in data:
                        got_commands.append({'command': 'lux', 'value': data['lux']})
                    if 'illumination' in data:
                        got_commands.append({'command': 'illumination', 'value': data['illumination']})
                    if 'temperature' in data:
                        got_commands.append({'command': 'temperature', 'value': round(data['temperature'] / 100, 2)})
                    if 'humidity' in data:
                        got_commands.append({'command': 'humidity', 'value': round(data['humidity'] / 100, 2)})
                    if 'pressure' in data:
                        got_commands.append({'command': 'pressure_kpa', 'value': round(data['pressure'] / 1000, 2)})
                        got_commands.append({'command': 'pressure_mm', 'value': round(data['pressure'] / 1000 * 7.50062, 2)})
                    if command == 'report' and message_data['model'] in ['switch', 'sensor_switch.aq2', 'sensor_switch.aq3']:
                        got_commands.append({'command': data['status'], 'value': 1})
                    if 'channel_0' in data:
                        status = data['channel_0']
                        if status in ['on', 'off']:
                            got_commands.append({'command': 'channel_0', 'value': 1 if status == 'on' else 0})
                        else:
                            got_commands.append({'command': f'{status}0', 'value': 1})
                    if 'channel_1' in data:
                        status = data['channel_1']
                        if status in ['on', 'off']:
                            got_commands.append({'command': 'channel_1', 'value': 1 if status == 'on' else 0})
                        else:
                            got_commands.append({'command': f'{status}1', 'value': 1})
                    if 'dual_channel' in data:
                        got_commands.append({'command': data['dual_channel'], 'value': 1})
                    if 'alarm' in data:
                        got_commands.append({'command': 'alarm', 'value': data['alarm']})
                    if 'density' in data:
                        got_commands.append({'command': 'density', 'value': data['density']})
                    if command == 'report' and data.get('status') == 'motion':
                        got_commands.append({'command': 'motion', 'value': 1})
                    if 'no_motion' in data:
                        got_commands.append({'command': 'no_motion', 'value': data['no_motion']})
                    if data.get('status') in ['iam', 'leak', 'no_leak']:
                        got_commands.append({'command': data['status'], 'value': 1 if data['status'] in ['iam', 'leak'] else 0})
                    if 'no_close' in data:
                        got_commands.append({'command': 'no_close', 'value': data['no_close']})
                    if 'voltage' in data:
                        voltage = data['voltage'] * 0.001
                        got_commands.append({'command': 'voltage', 'value': voltage})
                        mvolts = data['voltage']
                        if mvolts >= 3000:
                            battery_level = 100
                        elif mvolts > 2900:
                            battery_level = 100 - ((3000 - mvolts) * 58) / 100
                        elif mvolts > 2740:
                            battery_level = 42 - ((2900 - mvolts) * 24) / 160
                        elif mvolts > 2440:
                            battery_level = 18 - ((2740 - mvolts) * 12) / 300
                        elif mvolts > 2100:
                            battery_level = 6 - ((2440 - mvolts) * 6) / 340
                        else:
                            battery_level = 0
                        got_commands.append({'command': 'battery_level', 'value': battery_level})
                    if command == 'report' and data.get('status') and message_data['model'] in ['magnet', 'sensor_magnet.aq2']:
                        got_commands.append({'command': 'status', 'value': 1 if data['status'] == 'close' else 0})

                    for c in got_commands:
                        command, value = c['command'], c['value']
                        cmd_rec = session.query(Command).filter(Command.device_id == device_id, Command.title == command).one_or_none()
                        if not cmd_rec:
                            cmd_rec = Command(device_id=device_id, title=command)
                            session.add(cmd_rec)
                            
                        old_value = cmd_rec.value if cmd_rec else None
                        cmd_rec.value = str(value)
                        cmd_rec.updated = datetime.datetime.now()

                        if cmd_rec.linked_object and cmd_rec.linked_property:
                            setProperty(cmd_rec.linked_object + "." + cmd_rec.linked_property,value,self.name)

                        if cmd_rec.linked_object and cmd_rec.linked_method:
                            if str(value) != old_value or \
                                command == 'motion' or \
                                command == 'click0' or \
                                command == 'click1' or \
                                command == 'both_click' or \
                                command == 'alarm' or \
                                command == 'iam' or \
                                command == 'leak' or \
                                device.type == 'sensor_switch.aq3' or \
                                device.type == 'sensor_switch.aq2' or \
                                device.type == 'switch' or \
                                device.type == 'cube':
                            
                                callMethod(cmd_rec.linked_object + "." + cmd_rec.linked_property, message_data, self.name)

                    session.commit()
                
    def make_signature(self, token, key):
        from Crypto.Cipher import AES
        init_vector = bytes(bytearray.fromhex('17996d093d28ddb3ba695a2e6f58562e'))
        encryptor = AES.new(key.encode('utf-8'), AES.MODE_CBC, IV=init_vector)
        ciphertext = encryptor.encrypt(token.encode('utf-8'))
        return ''.join('{:02x}'.format(x) for x in ciphertext)

    def changeLinkedProperty(self, obj, prop_name, value):
        self.logger.info("PropertySetHandle: %s.%s=%s",obj,prop_name,value)
        with session_scope() as session:
            properties = session.query(Command).filter(Command.linked_object == obj, Command.linked_property == prop_name).all()
            for prop in properties:
                device = session.query(Device).filter(Device.id == prop.device_id).one()
                ip = device.gate_ip
                gate = device
                key = None
                if device.type != 'gateway':
                    gate = session.query(Device).filter(Device.type == 'gateway', Device.gate_ip == ip).one()
                    if gate:
                        key = gate['GATE_KEY']
                        token = gate['TOKEN']
                    else:
                        self.logger.error('Cannot find gateway key')
                        continue
                else:
                    token = device.token
                    key = device.gate_key
                    
                data = {'sid': device.sid, 'short_id': 0}
                cmd_data = {}

                if prop.title == 'status' and device.type in ['plug', 'ctrl_86plug.aq1']:
                    data['cmd'] = 'write'
                    data['model'] = device.type
                    cmd_data['status'] = 'on' if value else 'off'

                if prop.title == 'channel_0':
                    data['cmd'] = 'write'
                    data['model'] = device.type
                    cmd_data['channel_0'] = 'on' if value else 'off'

                if prop.title == 'channel_1':
                    data['cmd'] = 'write'
                    data['model'] = device.type
                    cmd_data['channel_1'] = 'on' if value else 'off'

                if prop.title == 'curtain_level':
                    data['cmd'] = 'write'
                    data['model'] = device.type
                    value = max(0, min(100, int(value)))
                    cmd_data['curtain_level'] = str(value)

                if prop.title == 'curtain_status':
                    if value in ['open', 'close', 'stop', 'auto']:
                        data['cmd'] = 'write'
                        data['model'] = device.type
                        cmd_data['curtain_status'] = str(value)
                    else:
                        return

                if prop.title == 'brightness':
                    rgb_cmd = session.query(Command).filter(Command.title == 'rgb', Command.device_id == prop.device_id).one()
                    if rgb_cmd:
                        rgb_value = rgb_cmd.value
                        value = f"{value:02x}{rgb_value}"
                    send_value = int(value, 16)
                    data['cmd'] = 'write'
                    data['model'] = 'gateway'
                    cmd_data['rgb'] = send_value

                if prop.title == 'rgb':
                    value = value.lstrip('#')
                    if len(value) < 8 and int(value, 16) > 0:
                        br_cmd = session.query(Command).filter(Command.title == 'brightness', Command.device_id == prop.device_id).one()
                        br_value = int(br_cmd.value) if br_cmd else None
                        value = f"{br_value:02x}{value}" if br_value else f"ff{value}"
                    send_value = int(value, 16)
                    data['cmd'] = 'write'
                    data['model'] = 'gateway'
                    cmd_data['rgb'] = send_value

                if prop.title == 'ringtone':
                    data['cmd'] = 'write'
                    data['model'] = 'gateway'
                    if value in ['', 'stop']:
                        cmd_data['mid'] = 10000
                    else:
                        tmp = value.split(',')
                        value = int(tmp[0].strip())
                        vol = int(tmp[1].strip()) if len(tmp) > 1 else None
                        cmd_data['mid'] = value
                        if vol is not None:
                            cmd_data['vol'] = vol

                print(token, key, data)
                if 'cmd' in data:
                    if data['cmd'] == 'write':
                        if gate.type == 'gateway':
                            cmd_data['key'] = self.make_signature(token, key)
                            data['data'] = json.dumps(cmd_data)
                        elif gate.type == 'acpartner.v3':
                            data['key'] = self.make_signature(token, key)
                            data['params'] = cmd_data
                        
                    print(token, key, data)
                    self.send_message(data,ip)
                