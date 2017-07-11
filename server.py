"""
   Copyright 2017 Fastboot Mobile, LLC.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""

from tornado import websocket, web
from model import *
import threading
import json
import nacl.encoding
import nacl.signing
from nacl.public import PrivateKey, Box, PublicKey
import nacl.exceptions
import base64
import redis
import time
import configparser
import os
import datetime

clients = []
client_name_list = []
client_mapped = {}
client_mapped_lock = threading.Lock()

pingStarted = False

config = configparser.ConfigParser()
config.read('config.ini')

redis_host = config['redisinfo']['host']
redis_port = config['redisinfo']['port']

debug_mode = config['serversettings']['debug']
serverTimeout = int(config['serversettings']['timeout'])  # Seconds before socket timeout (needs setting in nginx)
pingDelay = int(config['serversettings']['delay'])  # seconds between pings for each device
secret = config['serversettings']['secret']

print("Timeout is : " + str(serverTimeout))
print("Ping Delay is : " + str(pingDelay))

if debug_mode == "true" or debug_mode == "True":
    debug_mode = True
else:
    debug_mode = False

cache = redis.StrictRedis(host=redis_host, port=redis_port, db=0)

def onMessageQueued(message):

    dev_id = message['data'].decode()

    if dev_id in client_mapped:
        messages = cache.hgetall(dev_id)

        client_mapped_lock.acquire()
        client_socket = client_mapped[dev_id]
        client_mapped_lock.release()

        for key in messages:
            print("sending to " + dev_id)
            client_socket.write_message(messages[key])
            time.sleep(0.25)


p = cache.pubsub()
p.subscribe(**{'__keyevent@0__:hset': onMessageQueued})
thread = p.run_in_thread(sleep_time=0.001)

process_error = ""


def processToken(token):

    token_parts = token.split('.')

    header_txt = base64.b64decode(token_parts[0]).decode()
    header_json = json.loads(header_txt)

    verify = nacl.signing.VerifyKey(header_json['API_KEY'], encoder=nacl.encoding.HexEncoder)

    signature = token_parts[2]
    to_verify = token_parts[0] + "." + token_parts[1]  # combine the two parts of the token for verification

    apps = session.query(Application).filter(Application.api_key == header_json['API_KEY'])

    global process_error

    if apps.count() != 1:
        process_error = "App with api_key " + header_json['API_KEY'] + " not found"
        return None

    curr_app = apps.first()

    to = header_json['to']
    app_key = to.split(".")

    # First section of the "to" address is the app key
    if not app_key[0] == curr_app.application_key:
        return None

    d = base64.b64encode(base64.b64decode(signature) + to_verify.encode())

    try:
        verify.verify(d, encoder=nacl.encoding.Base64Encoder)
    except nacl.exceptions.BadSignatureError:
        print("BAD SIGNATURE")
        process_error = "Could not verify data"
        return None

    print("GOOD SIGNATURE")

    return token


def pingAllClinets():
    client_mapped_lock.acquire()
    clients_local = client_mapped
    client_mapped_lock.release()

    print("PINGING ALL CLIENTS NOW")

    for client in clients_local:
        try:
            clients_local[client].ping("PING".encode())
        except Exception :
            print("Could Not Ping Client")

    threading.Timer(pingDelay, pingAllClinets).start()


class tokenSendAPI(web.RequestHandler):
    def post(self):

        token = self.get_argument("token", None)
        if token is None:
            self.write_error(404)
            return

        status_dict = {}

        b64_data = processToken(token)

        if b64_data is None:
            status_dict["status"] = "SIGNATURE_ERROR"
            global process_error
            status_dict["extra_error"] = process_error
            self.write(json.dumps(status_dict))
            return

        sig = token.split('.')[2]

        token_parts = b64_data.split('.')

        plain_header = base64.b64decode(token_parts[0]).decode()
        json_header = json.loads(plain_header)

        plain_body = base64.b64decode(token_parts[1]).decode()
        json_body = json.loads(plain_body)

        target_client = json_header['to']
        target_message = json_body['data']
        target_nonce = json_body['nonce']

        header_dict = {}
        header_dict['alg'] = "FM-1"
        header_dict['typ'] = "JWT"
        header_dict['srv_v'] = "v0.0"
        header_dict['sig'] = sig
        header_dict['to'] = target_client

        body_dict = {}
        body_dict['data'] = target_message
        body_dict['nonce'] = target_nonce

        header_json = json.dumps(header_dict)
        header_b64 = base64.b64encode(header_json.encode())

        body_json = json.dumps(body_dict)
        body_b64 = base64.b64encode(body_json.encode())

        output = header_b64.decode() + "." + body_b64.decode()

        curr_installs = session.query(Installs).filter(Installs.install_id == target_client)

        if curr_installs.count() < 1:
            status_dict["status"] = "INSTALL_NOT_REGISTERED"
        else:
            curr_install = curr_installs.first()
            curr_install.last_seen = datetime.datetime.now()
            cache.hset(curr_install.device.public_id, sig, output)
            cache.expire(curr_install.device.public_id, "86400")  # For noe expire the key from redis after 1 day
            print ("added to redis queue for dev_id : " + curr_install.device.public_id)
            status_dict["status"] = "OK"

        self.write(json.dumps(status_dict))
        return


class WSHandler(websocket.WebSocketHandler):

    def check_origin(self, origin):
        return True

    def open(self):
        print ('connection opened...')

        header_dict = {}
        header_dict['alg'] = "FM-1"
        header_dict['typ'] = "JWT"
        header_dict['srv_v'] = "v0.0"

        ret_dict = {}
        header_dict["CMD"] = "START"

        ret_dict['TIMEOUT'] = str(serverTimeout)

        header_json = json.dumps(header_dict)
        header_b64 = base64.b64encode(header_json.encode())

        body_json = json.dumps(ret_dict)
        body_b64 = base64.b64encode(body_json.encode())

        self.write_message(header_b64.decode() + "." + body_b64.decode())

        global pingStarted

        if pingStarted is False:
            print("Staring PINGs")
            threading.Timer(15, pingAllClinets).start()
            pingStarted = True

    def on_message(self, message):

        print ('received:', message)

        message_parts = message.split(".")

        message_header = base64.b64decode(message_parts[0])
        message_body = base64.b64decode(message_parts[1])#

        print(message_header)
        print(message_body)

        message_header_json = json.loads(message_header.decode())
        message_body_json = json.loads(message_body.decode())

        header_dict = {}
        header_dict['alg'] = "FM-1"
        header_dict['typ'] = "JWT"
        header_dict['srv_v'] = "v0.0"

        ret_dict = {}

        if "CMD" in message_header_json:

            if message_header_json["CMD"] == "REG_DEV":
                id = message_body_json["DEVICE_ID"];
                header_dict["CMD"] = message_header_json["CMD"]

                client_mapped_lock.acquire()
                if id in client_mapped:
                    client_mapped[id].close()

                cur_dev = session.query(Device).filter(Device.public_id == id).first()

                if cur_dev is None:
                    dev = Device()
                    dev.public_id = id
                    dev.last_seen = datetime.datetime.now()
                    session.add(dev)
                    session.commit()
                else :
                    cur_dev.last_seen = datetime.datetime.now()
                    session.commit()

                ret_dict["STATUS"] = "OK"
                client_mapped[id] = self
                print ("clientID " + id + " registered")
                client_mapped_lock.release()

            if message_header_json["CMD"] == "REG_INSTALL":
                install_id = message_body_json["INSTALL_ID"]
                dev_id = message_body_json["DEVICE_ID"]

                header_dict["CMD"] = message_header_json["CMD"]
                ret_dict["INSTALL_ID"] = message_body_json["INSTALL_ID"]

                curr_installs = session.query(Installs).filter(Installs.install_id == install_id).all()


                app_key = install_id.split('.')[0]
                curr_app = session.query(Application).filter(Application.application_key == app_key).first()
                cur_dev = session.query(Device).filter(Device.public_id == dev_id).first()

                print(curr_app.desc)

                if curr_app is None :
                    ret_dict["STATUS"] = "FAIL"
                    print ("could not detect app for " + app_key)
                elif cur_dev is None :
                    ret_dict["STATUS"] = "FAIL"
                    print ("device not registered " + dev_id)
                elif len(curr_installs) > 0:
                    curr_install = curr_installs.first()
                    if curr_install.device.public_id == dev_id:
                        ret_dict["STATUS"] = "OK"
                        print ("installID " + install_id + " already registered to " + dev_id)
                    else:
                        ret_dict["STATUS"] = "FAIL"
                else:
                    new_install = Installs()
                    new_install.install_id = install_id
                    new_install.device = cur_dev
                    new_install.app = curr_app
                    new_install.last_seen = datetime.datetime.now()
                    session.add(new_install)
                    session.commit()
                    ret_dict["STATUS"] = "OK"
                    print ("installID " + install_id + " registered to " + dev_id)
            if message_header_json["CMD"] == "ACK":

                    dev_id = message_body_json["DEVICE_ID"]
                    key = message_body_json["SIG"]

                    if self == client_mapped[dev_id]:
                        print("ACK Message: " + key)
                        cache.hdel(dev_id, key)

        header_json = json.dumps(header_dict)
        header_b64 = base64.b64encode(header_json.encode())

        body_json = json.dumps(ret_dict)
        body_b64 = base64.b64encode(body_json.encode())

        output = header_b64.decode() + "." + body_b64.decode()
        print(output)

        self.write_message(output)

    def on_close(self):

        for key in client_mapped:
            if client_mapped[key] == self:
                client_mapped_lock.acquire()
                del client_mapped[key]
                client_mapped_lock.release()
                break

        try:
            clients.remove(self)
        except Exception :
            print("No need to remove client")

        print('connection closed...')

    def on_pong(self, data):
        print('got pong', data)


class IndexView(web.RequestHandler):
    def get(self):
        self.render("index.html")

settings = {
    "cookie_secret": secret,
    "template_path": "templates",
    "debug": debug_mode,
}

class IndexView(web.RequestHandler):
    def get(self):
        self.render("index.html")

application = web.Application([
    (r'/', IndexView),
    (r'/ws', WSHandler),
    (r'/send', tokenSendAPI),
    (r'/static/(.*)', web.StaticFileHandler, {'path': './static'}),
], **settings)
