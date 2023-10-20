from flask import Flask, request, jsonify
import socket
import struct
import pymongo

app = Flask(__name__)

client = pymongo.MongoClient("mongodb://localhost:27017/cp6.cp")
db = client["cp6"] 
collection = db["cp"]  

raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))  # 3 == ETH_P_ALL

@app.route('/start_capture', methods=['POST'])
def start_capture():
    interface = request.json.get('interface', 'eth0')  
    raw_socket.bind((interface, 0))
    raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    while True:
        packet, _ = raw_socket.recvfrom(65536)
        process_and_store_packet(packet)
    return "Captura de pacotes iniciada", 201

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    raw_socket.close()
    return "Captura de pacotes encerrada", 200

def process_and_store_packet(packet):
    # primeiros 20 bytes em hexadecimal
    packet_hex = ":".join("{:02x}".format(ord(byte)) for byte in packet[:20])
    packet_json = {"packet_data": packet_hex}
    collection.insert_one(packet_json)

if __name__ == "__main__":
    app.run(debug=True)
