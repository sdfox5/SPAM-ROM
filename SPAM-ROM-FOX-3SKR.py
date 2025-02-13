import requests
import time
import socket
import os
import sys
import threading
import re
import random
import subprocess
import select
import json
import urllib3
import struct
website = "https://api-ghost.vercel.app/FFcrypto/{id}"
def fake_friend(client, id: str):
        if len(id) == 8:
            packet = "060000007708d4d7faba1d100620022a6b08cec2f1051a1b5b3030464630305d2b2b20202020434f4445585b3030464630305d32024d454049b00101b801e807d801d4d8d0ad03e001b2dd8dae03ea011eefbca8efbca5efbcb2efbcafefbcb3efbca8efbca9efbcadefbca1efa3bf8002fd98a8dd03900201d00201"
            packet = re.sub(r'cec2f105', id, packet)
            client.send(bytes.fromhex(packet))
        elif len(id) == 10:
            packet = "060000006f08d4d7faba1d100620022a6308fb9db9ae061a1c5b3030464630305d2b2be385a4434f44455820205b3030464630305d32024d454040b00113b801e71cd801d4d8d0ad03e00191db8dae03ea010a5a45522d49534b494e47f00101f801911a8002fd98a8dd03900201d0020ad80221"
            packet = re.sub(r'fb9db9ae06', id, packet)
            client.send(bytes.fromhex(packet))
        else:
            print(id)
def Encrypt_ID(id):
        api_url = website.format(id=id)
        try:
            response = requests.get(api_url)
            if response.status_code == 200:
                return response.text
            else:
                print("&#1601;&#1588;&#1604; &#1601;&#1610; &#1580;&#1604;&#1576; &#1575;&#1604;&#1576;&#1610;&#1575;&#1606;&#1575;&#1578;. &#1585;&#1605;&#1586; &#1575;&#1604;&#1581;&#1575;&#1604;&#1577;:", response.status_code)
                return None
        except requests.RequestException as e:
            print("&#1601;&#1588;&#1604; &#1575;&#1604;&#1591;&#1604;&#1576;:", e)
            return None
####################################
def send_msg_friends(replay, packet):
	replay  = replay.encode('utf-8')
	replay = replay.hex()
	hd = packet[0:8]
	packetLength = packet[8:10]
	paketBody = packet[10:32]
	pyloadbodyLength = packet[32:34]
	pyloadbody2 = packet[34:60]
	pyloadlength = packet[60:62]
	pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
	Tipy = packet[int(int(len(pyloadtext))+62):]
	NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])
	if len(NewTextLength) ==1:
		NewTextLength = "0"+str(NewTextLength)
	Nepalh = hex(((int(f'0x{packetLength}', 16) - int((len(pyloadtext))//2) ) ) + int(len(replay)//2) )[2:]
	Nepylh = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2))  )+ int(len(replay)//2) )[2:]
	st_pack = hd + Nepalh + paketBody + Nepylh + pyloadbody2 + NewTextLength + replay + Tipy
	return st_pack
def send_msg_clan(replay, packet):
	replay  = replay.encode('utf-8')
	replay = replay.hex()
	hd = packet[0:8]
	packetLength = packet[8:10] #
	paketBody = packet[10:32]
	pyloadbodyLength = packet[32:34]#
	pyloadbody2 = packet[34:64]
	if "googleusercontent" in str(bytes.fromhex(packet)):
		pyloadlength = packet[64:68]#
		pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
		Tipy = packet[int(int(len(pyloadtext))+68):]
	elif "https" in str(bytes.fromhex(packet)) and "googleusercontent" not in str(bytes.fromhex(packet)):
		pyloadlength = packet[64:68]#
		pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
		Tipy = packet[int(int(len(pyloadtext))+68):]
		print(bytes.fromhex(pyloadlength))
	else:
		pyloadlength = packet[64:66]#
		pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
		Tipy = packet[int(int(len(pyloadtext))+66):]
	NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])
	if len(NewTextLength) ==1:
		NewTextLength = "0"+str(NewTextLength)
	NewpaketLength = hex(((int(f'0x{packetLength}', 16) - int(len(pyloadtext)//2) ) - int(len(pyloadlength))) + int(len(replay)//2) + int(len(NewTextLength)))[2:]
	NewPyloadLength = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2)) -int(len(pyloadlength)) )+ int(len(replay)//2) + int(len(NewTextLength)))[2:]
	st_pack = hd + NewpaketLength +paketBody + NewPyloadLength +pyloadbody2+NewTextLength+ replay + Tipy
	return st_pack
####################################
spamm = False
SOCKS_VERSION = 5
#################################### 
username = "bot"
password = "bot"
op = None
clientC = None
add_fake = False
packet = b''
server_list = []
def handle_client(connection):
    version, nmethods = connection.recv(2)
    methods = get_available_methods(nmethods, connection)
    if 2 not in set(methods):
        connection.close()
        return
    connection.sendall(bytes([SOCKS_VERSION, 2]))
    if not verify(connection):
        return
    version, cmd, _, address_type = connection.recv(4)
    if address_type == 1:
        address = socket.inet_ntoa(connection.recv(4))
    elif address_type == 3:
        domain_length = connection.recv(1)[0]
        address = connection.recv(domain_length).decode('utf-8')
        address = socket.gethostbyname(address)
    port = int.from_bytes(connection.recv(2), 'big', signed=False)
    port2 = port
    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote.connect((address, port))
    serverlog(address, port)
    bind_address = remote.getsockname()
    addr = int.from_bytes(socket.inet_aton(bind_address[0]), 'big', signed=False)
    port = bind_address[1]
    reply = b"".join([
        SOCKS_VERSION.to_bytes(1, 'big'),
        int(0).to_bytes(1, 'big'),
        int(0).to_bytes(1, 'big'),
        int(1).to_bytes(1, 'big'),
        addr.to_bytes(4, 'big'),
        port.to_bytes(2, 'big')
    ])
    connection.sendall(reply)
    exchange_loop(connection, remote, port2)
####################################
def verify(connection):
    version = connection.recv(1)[0]
    username_len = connection.recv(1)[0]
    username_received = connection.recv(username_len).decode('utf-8')
    password_len = connection.recv(1)[0]
    password_received = connection.recv(password_len).decode('utf-8')
    if username_received == username and password_received == password:
        connection.sendall(bytes([version, 0]))
        return True
    connection.sendall(bytes([version, 0xFF]))
    connection.close()
    return False
####################################
def get_available_methods(nmethods, connection):
    return [connection.recv(1)[0] for _ in range(nmethods)]
####################################
def exchange_loop(client, remote, port):
    global spamm
    global pack, op, clientC
    if port == 39699:
        clientC = client
        op = client
    while True:
        try:
            r, w, e = select.select([client, remote], [], [])
            if client in r:
                dataC = client.recv(4096)
                
                if spamm and '0e15' in dataC.hex()[0:4]:
                    print("SPAMMING ACTIVE: Sending packets...")
                    counter = 0
                    for _ in range(30000):
                        try:
                            remote.send(dataC)
                            counter += 1
                            if counter == 10:
                                time.sleep(0.005)
                                counter = 0
                        except (BrokenPipeError, ConnectionResetError) as e:
                            print(f"Error sending spam data to remote: {e}")
                            break 
                try:
                    if remote.send(dataC) <= 0:
                        break
                except (BrokenPipeError, ConnectionResetError) as e:
                    print(f"Error sending data from client to remote: {e}")
                    break
            if remote in r:
                try:
                    dataS = remote.recv(4096)
                    if "0f0000" in dataS.hex()[0:6] and "0f15" in dataC.hex()[0:4] and add_fake == True:
                        time.sleep(5)
                        id_add = dataS.hex()[-10:]
                        print(id_add)
                        op.send(bytes.fromhex(f"060000006808d4d7faba1d100620022a5c08{id_add}1a1b5b4642423131375d4344582be385a4464f58585b4642423131375d32024d45404db00113b801a528d801d4d8d0ad03e00101b801e807f00101f8019a018002fd98a8dd03900201d0020cd8022ee002b2e9f7b103"))
                    if "0f0000" in dataS.hex()[0:6] and len(dataS.hex()) == 52 and "0f15" in dataC.hex()[0:4] and add_fake == True:
                        time.sleep(5)
                        id_add = dataS.hex()[-10:]
                        op.send(bytes.fromhex(f"060000006808d4d7faba1d100620022a5c08{id_add}1a1b5b4642423131375d4344582be385a4464f58585b4642423131375d32024d45404db00113b801a528d801d4d8d0ad03e00101b801e807f00101f8019a018002fd98a8dd03900201d0020cd8022ee002b2e9f7b103"))
                    if b"/FOX" in dataS:
                        i = re.split('/FOX', str(dataS))[1]
                        if '***' in i:
                            i = i.replace('***', '106')
                        id = str(i).split('(\\x')[0]
                        id = Encrypt_ID(id)
                        fake_friend(op, id)
                    if b'/SPAM' in dataS and '1200' in dataS.hex()[0:4]:
                        spamm = True
                        pack = dataS.hex()
                        client.send(bytes.fromhex(send_msg_clan("[00FF00][b][c] SPAMM STARTED...", pack)))
                        print("SPAMM STARTED...")
                except (BrokenPipeError, ConnectionResetError) as e:
                    print(f"Error sending data from remote to client: {e}")
                    break
                try:
                    if client.send(dataS) <= 0:
                        break
                except (BrokenPipeError, ConnectionResetError) as e:
                    print(f"Error sending data from client to remote: {e}")
        except Exception as e:
            print(f"General error in exchange_loop: {e}")
            break
####################################
def serverlog(address, port):
    server_info = f"{address}:{port}"
    if server_info not in server_list:
        server_list.append(server_info)
####################################
def run(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen()
    print(f"Proxy running on ⟩⟩ :   {host}, {port}")
    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=handle_client, args=(conn,))
        t.start()
####################################
if __name__ == "__main__":
#    threading.Thread(target=menu, daemon=True).start()
    run("127.0.0.1", 1080)