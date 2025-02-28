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
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
####################################
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_MAGENTA = "\033[95m"
COLOR_CYAN = "\033[96m"
COLOR_WHITE = "\033[97m"
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_UNDERLINE = "\033[4m" 
####################################
username = "username"
password = "password"
SOCKS5_VERSION = 5
server_list = []
op = None
clientC = None
spam_emote = False
spamm = False
back_normal = False
back_spam = False
yt = None
add_fake = False
comand = False
romcode = None
####################################
def get_random_color():
    color = random.choice([
        "[cُ][bَ][FF0000]",
        "[cُ][bَ][00FF00]",
        "[cُ][bَ][0000FF]",
        "[cُ][bَ][FFFF00]",
        "[cُ][bَ][FFA500]",
        "[cُ][bَ][800080]",
        "[cُ][bَ][808080]",
        "[cُ][bَ][FFD700]",
        "[cُ][bَ][00FFFF]",
        "[cُ][bَ][FF1493]",
        "[cُ][bَ][8A2BE2]",
        "[cُ][bَ][A52A2A]",
        "[cُ][bَ][DC143C]",
        "[cُ][bَ][00CED1]",
        "[cُ][bَ][FF4500]",
        "[cُ][bَ][2E8B57]",
        "[cُ][bَ][ADFF2F]",
        "[cُ][bَ][4682B4]",
        "[cُ][bَ][40E0D0]",
        "[cُ][bَ][DA70D6]",
        "[cُ][bَ][F4A460]",
        "[cُ][bَ][FF6347]",
        "[cُ][bَ][7FFF00]",
        "[cُ][bَ][BA55D3]",
        "[cُ][bَ][FF69B4]",
        "[cُ][bَ][E9967A]",
    ])
    return color
#####EDIT PACKET FOR SEND MESSAGEL#####
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
def gen_squad(clisocks, packet: str):
        header = packet[0:62]
        lastpacket = packet[64:]
        squadcount = "04"
        NewSquadData = header + squadcount + lastpacket
        clisocks.send(bytes.fromhex(NewSquadData))
def gen_msg4(packet, content):
        content = content.encode("utf-8")
        content = content.hex()
        header = packet[0:8]
        packetLength = packet[8:10]
        packetBody = packet[10:32]
        pyloadbodyLength = packet[32:34]
        pyloadbody2 = packet[34:62]
        pyloadlength = packet[62:64]
        pyloadtext= re.findall(r"{}(.*?)28".format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+64):]
        NewTextLength = (hex((int(f"0x{pyloadlength}", 16) - int(len(pyloadtext)//2) ) + int(len(content)//2))[2:])
        if len(NewTextLength) == 1:
                NewTextLength = "0"+str(NewTextLength)
        NewpaketLength = hex(((int(f"0x{packetLength}", 16) - int((len(pyloadtext))//2) ) ) + int(len(content)//2) )[2:]
        NewPyloadLength = hex(((int(f"0x{pyloadbodyLength}", 16) - int(len(pyloadtext)//2)))+ int(len(content)//2) )[2:]
        NewMsgPacket = header + NewpaketLength + packetBody + NewPyloadLength + pyloadbody2 + NewTextLength + content + pyloadTile
        return str(NewMsgPacket)
def gen_msgv3(packet , replay):
        replay = replay.encode('utf-8')
        replay = replay.hex()
        hedar = packet[0:8]
        packetLength = packet[8:10] #
        paketBody = packet[10:32]
        pyloadbodyLength = packet[32:34]
        pyloadbody2= packet[34:60]
        pyloadlength = packet[60:62]
        pyloadtext= re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+62):]
        NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])
        if len(NewTextLength) == 1:
                NewTextLength = "0"+str(NewTextLength)
        NewpaketLength = hex(((int(f'0x{packetLength}', 16) - int((len(pyloadtext))//2) ) ) + int(len(replay)//2) )[2:]
        NewPyloadLength = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2)))+ int(len(replay)//2) )[2:]
        finallyPacket = hedar + NewpaketLength +paketBody + NewPyloadLength +pyloadbody2+NewTextLength+ replay + pyloadTile
        return str(finallyPacket)
def gen_msgv2_clan(replay  , packet):
    replay  = replay.encode('utf-8')
    replay = replay.hex()
    hedar = packet[0:8]
    packetLength = packet[8:10] #
    paketBody = packet[10:32]
    pyloadbodyLength = packet[32:34]#
    pyloadbody2= packet[34:64]
    if "googleusercontent" in str(bytes.fromhex(packet)):
        pyloadlength = packet[64:68]#
        pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+68):]
    elif "https" in str(bytes.fromhex(packet)) and "googleusercontent" not in str(bytes.fromhex(packet)):
        pyloadlength = packet[64:68]#
        pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+68):]
    else:
        pyloadlength = packet[64:66]#
        pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+66):]
    NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])    
    if len(NewTextLength) ==1:
        NewTextLength = "0"+str(NewTextLength)
    NewpaketLength = hex(((int(f'0x{packetLength}', 16) - int(len(pyloadtext)//2) ) - int(len(pyloadlength))) + int(len(replay)//2) + int(len(NewTextLength)))[2:]
    NewPyloadLength = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2)) -int(len(pyloadlength)) )+ int(len(replay)//2) + int(len(NewTextLength)))[2:]
    finallyPacket = hedar + NewpaketLength +paketBody + NewPyloadLength +pyloadbody2+NewTextLength+ replay + pyloadTile
    return finallyPacket
def gen_msgv2(replay  , packet):
    replay  = replay.encode('utf-8')
    replay = replay.hex()
    hedar = packet[0:8]
    packetLength = packet[8:10] #
    paketBody = packet[10:32]
    pyloadbodyLength = packet[32:34]#
    pyloadbody2= packet[34:60]
    pyloadlength = packet[60:62]#
    pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
    pyloadTile = packet[int(int(len(pyloadtext))+62):]
    NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])
    if len(NewTextLength) ==1:
        NewTextLength = "0"+str(NewTextLength)
    NewpaketLength = hex(((int(f'0x{packetLength}', 16) - int((len(pyloadtext))//2) ) ) + int(len(replay)//2) )[2:]
    NewPyloadLength = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2))  )+ int(len(replay)//2) )[2:]
    finallyPacket = hedar + NewpaketLength +paketBody + NewPyloadLength +pyloadbody2+NewTextLength+ replay + pyloadTile
    return finallyPacket
def send_msg(sock, packet, content, delay:int):
        time.sleep(delay)
        try:
                sock.send(bytes.fromhex(gen_msg4(packet, content)))              
                sock.send(bytes.fromhex(gen_msgv3(packet, content)))
        except Exception as e:
                pass
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
##############DEF LIKES###############

###############DEF INFO##############
def get_status(user_id):
    try:
        r = requests.get(f'https://ff.garena.com/api/antihack/check_banned?lang=en&uid={user_id}')
        if "0" in r.text:
            return f"{get_random_color()}▶PLAYER STATUS: {get_random_color()} Account Clear!"
        else:
            return "{get_random_color()}▶PLAYER STATUS: {get_random_color()} Account Ban!"
    except Exception as e:
        return f"Error checking status: {e}"
def get_player_info(user_id):
    try:
        cookies = {
            '_ga': 'GA1.1.2123120599.1674510784',
            '_fbp': 'fb.1.1674510785537.363500115',
            '_ga_7JZFJ14B0B': 'GS1.1.1674510784.1.1.1674510789.0.0.0',
            'source': 'mb',
            'region': 'MA',
            'language': 'ar',
            '_ga_TVZ1LG7BEB': 'GS1.1.1674930050.3.1.1674930171.0.0.0',
            'datadome': '6h5F5cx_GpbuNtAkftMpDjsbLcL3op_5W5Z-npxeT_qcEe_7pvil2EuJ6l~JlYDxEALeyvKTz3~LyC1opQgdP~7~UDJ0jYcP5p20IQlT3aBEIKDYLH~cqdfXnnR6FAL0',
            'session_key': 'efwfzwesi9ui8drux4pmqix4cosane0y',
        }
        headers = {
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Origin': 'https://shop2game.com',
            'Referer': 'https://shop2game.com/app/100067/idlogin',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 11; Redmi Note 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36',
            'accept': 'application/json',
            'content-type': 'application/json',
            'sec-ch-ua': '"Chromium";v="107", "Not=A?Brand";v="24"',
            'sec-ch-ua-mobile': '?1',
            'sec-ch-ua-platform': '"Android"',
            'x-datadome-clientid': '20ybNpB7Icy69F~RH~hbsvm6XFZADUC-2_--r5gBq49C8uqabutQ8DV_IZp0cw2y5Erk-KbiNZa-rTk1PKC900mf3lpvEP~95Pmut_FlHnIXqxqC4znsakWbqSX3gGlg',
        }
        json_data = {
            'app_id': 100067,
            'login_id': str(user_id),
            'app_server_id': 0,
        }
        response = requests.post(
            'https://shop2game.com/api/auth/player_id_login',
            cookies=cookies,
            headers=headers,
            json=json_data
        )

        if response.status_code == 200:
            player_info = response.json()
            if 'region' in player_info and 'nickname' in player_info:
                return {
                    "region": f"{get_random_color()}\n\n⏯PLAYER REGION: {player_info['region']}\n\n",
                    "nickname": f"{get_random_color()}\n\n⏭PLAYER NAME: {player_info['nickname']}\n\n"
                }
            else:
                return {"error": "Invalid response format"}
        else:
            return {"error": f"Failed to fetch player info: {response.status_code}"}

    except Exception as e:
        return {"error": f"Error fetching player info: {e}"}
##########DEF INFO REGION############
def getname(Id):    
    url = "https://shop2game.com/api/auth/player_id_login"
    headers = {
        "Accept": "application/json",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9,en;q=0.8",
        "Content-Type": "application/json",
        "Origin": "https://shop2game.com",
        "Referer": "https://shop2game.com/app",
        "sec-ch-ua": '"Google Chrome";v="111", "Not(A:Brand";v="8", "Chromium";v="111"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "Windows",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
        "x-datadome-clientid": "10BIK2pOeN3Cw42~iX48rEAd2OmRt6MZDJQsEeK5uMirIKyTLO2bV5Ku6~7pJl_3QOmDkJoSzDcAdCAC8J5WRG_fpqrU7crOEq0~_5oqbgJIuVFWkbuUPD~lUpzSweEa",
    }
    payload = {
        "app_id": 100067,
        "login_id": f"{Id}",
        "app_server_id": 0,
    }
    response = requests.post(url, headers=headers, json=payload)
    try:
        if response.status_code == 200:
            return response.json()['nickname']
        else:
            return("ERROR")
    except:
        return("Name unknown??")
####################################
def adjust_text_length(text, target_length=22, fill_char="20"):
    if len(text) > target_length:
        return text[:target_length]
    elif len(text) < target_length:
        fill_length = target_length - len(text)
        return text + (fill_char * (fill_length // len(fill_char)))[:fill_length]
    else:
        return text
####################################
####################################
##########CLASS SOCKET!!!#############
def handle_client(connection):
    try:
        version, nmethods = connection.recv(2)
        methods = get_available_methods(nmethods, connection)
        if 2 not in set(methods):
            connection.close()
            return
        connection.sendall(bytes([SOCKS5_VERSION, 2]))
        if not verify(connection):
            return
        version, cmd, _, address_type = connection.recv(4)
        if address_type == 1:
            address = socket.inet_ntoa(connection.recv(4))
        elif address_type == 3:
            domain_length = connection.recv(1)[0]
            domain = connection.recv(domain_length).decode('utf-8')
            address = socket.gethostbyname(domain)
        port = int.from_bytes(connection.recv(2), 'big', signed=False)
        port2 = port
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            remote.connect((address, port))
        except Exception as e:
            print(f"Failed to connect to remote: {e}")
            connection.close()
            return
        serverlog(address, port)
        bind_address = remote.getsockname()
        addr = int.from_bytes(socket.inet_aton(bind_address[0]), 'big', signed=False)
        port = bind_address[1]
        reply = b"".join([
            SOCKS5_VERSION.to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            int(1).to_bytes(1, 'big'),
            addr.to_bytes(4, 'big'),
            port.to_bytes(2, 'big')
        ])
        connection.sendall(reply)
        exchange_loop(connection, remote, port2)
    except Exception as e:
        print(f"ERROR IN handle_client: {e}")
def verify(connection):
    try:
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
    except Exception as e:
        print(f"ERROR IN verify: {e}")
        return False
def get_available_methods(nmethods, connection):
    try:
        return [connection.recv(1)[0] for _ in range(nmethods)]
    except Exception as e:
        print(f"ERROR IN get_available_methods: {e}")
        return []
def serverlog(address, port):
    server_info = f"{address}:{port}"
    if server_info not in server_list:
        server_list.append(server_info)
##########exchange_loop###############
def exchange_loop(client, remote, port):
    global spamm
    global pack, op, clientC
    if port == 39698:
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
                    for _ in range(9999999999999):
                        try:
                            remote.send(dataC)
                            counter += 1
                            if counter == 30:
                                time.sleep(0.000000005)
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
#############START BOT###############
def run(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen()
        print(f"Proxy running on ⟩⟩ : {host},{port}")
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn,))
            t.start()
    except Exception as e:
        print(f"ERROR IN run: {e}")
def start_bot():
    run("127.0.0.1", 3000)
if __name__ == "__main__":
    start_bot()
