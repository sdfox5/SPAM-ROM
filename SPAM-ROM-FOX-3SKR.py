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
def send_request(iddd):
    url = f"https://fox-encodeuid.onrender.com/encode?uid={iddd}"
    try:
        res = requests.get(url)
        res.raise_for_status()
        res_json = res.json()
        id = res_json.get("encode uid")
        if not id:
            print(f"Key 'encode uid' not found in response for ID: {iddd}")
            return
        dor = f"050000002008{id}100520162a1408aae2cafb0210d7c2bbb1032a0608{id}"
        try:
            clientC.send(bytes.fromhex(dor))
            print(f"Sent: {dor}")
        except ConnectionResetError:
            print("Connection reset by peer. Retrying or handling error...")
        except ValueError as e:
            print(f"Error sending {dor}: {e}")
    except requests.exceptions.RequestException as e:
        print(f"Request failed for ID {iddd}: {e}")
    except json.JSONDecodeError:
        print(f"Invalid JSON response for ID {iddd}: {res.text}")
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
                pass
                return None
        except requests.RequestException as e:
            pass
            return None
####################################
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
####################################
username = "bot"
password = "bot"
SOCKS5_VERSION = 5
server_list = []
op = None
clientC = None
spamm = False
yt = None
room_spam = False
add_fake = False
comand = False
romcode = None
msg_id = None
####################################
def fox_Msg(id, msg):
    url = f"https://missag.vercel.app/api?id={id}&txt={msg}&code=FOXC4"
    response = requests.get(url)    
    if response.status_code == 200:
        packet = response.text
        return packet
    else:
        return f" - Error: {response.status_code}"
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
        packetLength = packet[8:10]
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
          
def Clan(replay,packet):
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
	        
def send_msg(sock, packet, content, delay:int):
        time.sleep(delay)
        try:
                sock.send(bytes.fromhex(gen_msg4(packet, content)))  
                sock.send(bytes.fromhex(Clan(packet, content)))
                sock.send(bytes.fromhex(gen_msgv3(packet, content)))
        except Exception as e:
                pass

def Fr(sock, packet, content, delay:int):
        time.sleep(delay)
        try:
                sock.send(bytes.fromhex(send_msg_friends(packet, content)))  
        except Exception as e:
                pass                                
                
def Clan_msg(sock, packet, content, delay:int):
        time.sleep(delay)
        try:
                sock.send(bytes.fromhex(Clan(packet, content)))
        except Exception as e:
                pass   
def adjust_text_length(text, target_length=22, fill_char="20"):
    if len(text) > target_length:
        return text[:target_length]
    elif len(text) < target_length:
        fill_length = target_length - len(text)
        return text + (fill_char * (fill_length // len(fill_char)))[:fill_length]
    else:
        return text

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
    global codes, clientC, spamm, add_fake, op,romcode, room_spam, msg_id
    code_verified = False
    if port == 39698:
        clientC = client
        op = client
    try:
        while True:
            r, _, _ = select.select([client, remote], [], [])
            if client in r:
                dataC = client.recv(4096)
####################################
                if room_spam and '0e15' in dataC.hex()[0:4]:
                    counter = 0
                    for _ in range(9999999999999):
                        try:
                            remote.send(dataC)
                            counter += 1
                            if counter == 30:
                                time.sleep(0.000000005)
                                counter = 0
                        except (BrokenPipeError, ConnectionResetError) as e:
                            pass
####################################
                if '0515' in dataC.hex()[0:4] and len(dataC.hex()) >= 141  :
                    data_join=dataC
                if spamm and '0515' in dataS.hex()[0:4]:
                    counter = 0
                    for _ in range(30000):
                        try:
                            remote.send(data)
                            counter += 1
                            if counter == 10:
                                time.sleep(0.005)
                                counter = 0
                        except (BrokenPipeError, ConnectionResetError) as e:
                            print(f"Error sending spam data to remote: {e}")
                if remote.send(dataC) <= 0:
                    break
####################################
            if remote in r:
                dataS = remote.recv(4096)
                msg_id = dataS.hex()[12:22]
                if b"RAMADAN-MUBARAK-FREE" in dataS:
                    code_verified = True
                    id = dataS.hex()[12:22]
                    msg_activit = f"120000022d08{id}101220022aa00408{id}10{id}22f8025b4646443730305d5b635d5b625d0a594f555220434f44453a205b4646464646465d5b635d5b625d52414d4144414e2d4d55424152414b2d465245453a0a5b4646464646465d5b635d5b625d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d0a5b3261666133355d5b635d5b625d0a2d3e426f742049732041637469766174650a2d3e464f522053484f5720434f4d4d414e44532053454e443a20200a2f68656c70206f72202f7374617274206f722068656c70206f722073746172740a5b4646464646465d5b635d5b625d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d0a0a0a5b4646443730305d5b635d5b625d656e5b4646464630305d5b635d5b625d6a6f5b4646443730305d5b635d5b625d796564207768695b4646413530305d5b635d5b625d7420636f645b4646443730305d5b635d5b625d65782074655b4646413530305d5b635d5b625d616d200a5b4646464646465d5b635d5b625d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d0a0a28a083cabd064a250a0b4f5554e385a4414c56494e10e7b290ae0320d20128c1b7f8b103420737526164616121520261726a640a5e68747470733a2f2f6c68332e676f6f676c6575736572636f6e74656e742e636f6d2f612f414367386f634a614d4363556f6c4355397148576c6c2d79506e76516d3354782d304630304d30596a633350437737326f7a44503d7339362d63100118017200"
                    client.send(bytes.fromhex(msg_activit))
                pack = dataS.hex()
                if "0f0000" in dataS.hex()[0:6] and "0f15" in dataC.hex()[0:4] and add_fake == True:
                	time.sleep(5)
                	id_add = dataS.hex()[-10:]
                	print(id_add)
                	op.send(bytes.fromhex(f"060000006808d4d7faba1d100620022a5c08{id_add}1a1b5b3030464630305d6624e385a46b6f756e6f7a5b3030464646465d32024d45404db00113b801a528d801d4d8d0ad03e00101b801e807f00101f8019a018002fd98a8dd03900201d0020cd8022ee002b2e9f7b103"))
                if "0f0000" in dataS.hex()[0:6] and len(dataS.hex()) == 52 and "0f15" in dataC.hex()[0:4] and add_fake == True:
                   time.sleep(5)
                   id_add = dataS.hex()[-10:]
                   print(id_add)
                   op.send(bytes.fromhex(f"060000006808d4d7faba1d100620022a5c08{id_add}1a1b5b3030464630305d6624e385a46b6f756e6f7a5b3030464646465d32024d45404db00113b801a528d801d4d8d0ad03e00101b801e807f00101f8019a018002fd98a8dd03900201d0020cd8022ee002b2e9f7b103"))
                if '0e00' in dataS.hex()[0:4]:
                    for i in range(10):
                        pattern = fr"x0{str(i)}(\d+)Z"
                        match = re.search(pattern, str(dataS))
                        if match:
                            number = match.group(1)
                            global romcode
                            romcode = number
                            print(romcode)
                if code_verified and b"/ROM-CODE" in dataS:
                    newdataS2 = dataS.hex()
                    getin = client
                    rom = f"[b][i][c][7cfc00] - Code Room : {romcode}\n By : CODEX TEAM"
                    try:
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), rom, 0.001)).start()
                    except:
                        pass
####################################
                if code_verified and b'/SQUID-EMOTES' in dataS:
                    try:
                        dataS_str = dataS.decode('utf-8', errors='ignore')
                    except UnicodeDecodeError:
                        print("Failed to decode dataS. Skipping...")
                        return
                    ids = re.findall(r'/SQUID-EMOTES/(\d+)', dataS_str) + re.findall(r'/(\d+)', dataS_str)
                    if not ids:
                        print("No valid IDs found in dataS.")
                        return
                    print("Extracted IDs:", ids)
                    threads = []
                    for iddd in ids:
                        thread = threading.Thread(target=send_request, args=(iddd,))
                        threads.append(thread)
                        thread.start()
                    for thread in threads:
                        thread.join()
####################################
                if code_verified and b"/emotes1" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210d6fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes2" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210d2fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes3" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210d1fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes4" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210d0fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes5" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210cefbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes6" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210cdfbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes7" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210ccfbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes8" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210cbfbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes9" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210c4fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes10" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210c6fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes11" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210c7fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes12" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210c8fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes13" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210c9fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes14" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210cafbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes15" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210ccfbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes16" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210cbfbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                ####################################
                if code_verified and b"/emotes17" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210bdfbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes18" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210c1fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes19" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210c2fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes20" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210c3fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes21" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210cefbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes22" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210cdfbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes23" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210ccfbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes24" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210b9fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes25" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210c4fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes26" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210c6fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes27" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210c0fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes28" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210bbfbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes29" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210befbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes30" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210bdfbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes31" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210bffbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes32" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210bafbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                ####################################
                if code_verified and b"/emotes33" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210b8fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes34" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210affbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes35" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210b0fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes36" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210b1fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes37" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210b2fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes38" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210b3fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes39" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210b4fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes40" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210b5fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes41" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210b6fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes42" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210b7fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes43" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210a2fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes44" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210a3fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes45" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210a4fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes46" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210a5fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes47" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210a6fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes48" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210a7fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes49" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f""
                    clientC.send(bytes.fromhex(raks))
                ####################################
                if code_verified and b"/emotes50" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210a8fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes51" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210a9fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes52" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210aafbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes53" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210abfbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes54" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210acfbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes55" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210adfbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes56" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210aefbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes57" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb021099fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes58" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb02109afbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes59" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb02109bfbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes60" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb02109cfbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes61" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb02109dfbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes62" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb02109efbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes63" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb02109ffbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes64" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210a0fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes65" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb0210a1fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes66" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb021098fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes67" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb021097fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes68" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb021096fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes69" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb021095fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
                if code_verified and b"/emotes70" in dataS:
                    id = dataS.hex()[12:22]
                    raks = f"050000002008{id}100520162a1408aae2cafb021094fbb8b1032a0608{id}"
                    clientC.send(bytes.fromhex(raks))
####################################
                elif code_verified and  b"/region+" in dataS:
                             parts = dataS.split(b"/region+")
                             user_id = parts[1].split(b"\x28")[0].decode("utf-8")
                             b = get_player_info(user_id)
                             bb = get_status(user_id)
                             if "error" in bb:
                                 print(bb["error"])
                             else:
                                 threading.Thread(target=send_msg, args=(client, dataS.hex(), bb, 0.2)).start()
                                 reg = b["region"]
                                 nick = b["nickname"]
                                 threading.Thread(target=send_msg, args=(client, dataS.hex(), reg, 0.2)).start()
                                 threading.Thread(target=send_msg, args=(client, dataS.hex(), nick, 0.2)).start()
####################################
                if code_verified and  b"/help" in dataS or code_verified and  b"help" in dataS or code_verified and  b"/start" in dataS or code_verified and  b"start" in dataS:
                                try:
                                    id = dataS.hex()[12:22]
                                    msg_help_ar = f"120000085308{id}101220022ac61008{id}10{id}229e0f0a5b3837434545425d5b635d5b625d435b3030424646465d5b635d5b625d4f5b3145393046465d5b635d5b625d445b3030303046465d5b635d5b625d455b3030303038425d5b635d5b625d58205b3837434545425d5b635d5b625d545b3030424646465d5b635d5b625d455b3145393046465d5b635d5b625d415b3030303046465d5b635d5b625d4d0a5b3830303038305d5b635d5b625d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d0a0a0a5b3233393742355d5b635d5b625dd8a7d984d8a3d988d8a7d985d8b120d8a7d984d985d8aad8a7d8add8a920d981d98a20d8a7d984d8a8d988d8aa20d987d98a3a200a0a0a5b3837434545425d5b635d5b625dd8a7d984d8b5d8afd98ad98220d8a7d984d988d987d985d98a3a200a0a5b4646433132355d5b625d0a2f696431323334353637380a0a0a5b3837434545425d5b635d5b625d20d8b3d8a8d8a7d98520d8b7d984d8a8d8a7d8aa20d8a7d984d8a7d986d8b6d985d8a7d985203a200a0a5b4646433132355d5b625d0a40696e764f4e0a40696e764f46460a0a0a5b3837434545425d5b635d5b625dd8aad8add988d98ad98420d8a7d984d8b3d983d988d8a7d8af20d8a5d984d989203520d984d8a7d8b9d8a8d98ad9863a200a0a5b4646433132355d5b625d0a2f35730a0a0a5b3837434545425d5b635d5b625dd8aad8add988d98ad98420d8a7d984d8b3d983d988d8a7d8af20d8a5d984d989203620d984d8a7d8b9d8a8d98ad9863a200a0a5b4646433132355d5b625d0a2f36730a0a0a5b3837434545425d5b635d5b625dd8a7d984d8a7d98ad985d988d8aad8a7d8aa2053515549443a200a20200a5b4646433132355d5b625d0a2f53515549442d454d4f5445532f31323334353637382f363730313638373438382f373232393337323932373339322f3534383338353237390a0a0a5b3837434545425d5b635d5b625dd8b3d8a8d8a7d98520d8a7d984d8bad8b1d981d8a93a200a0a5b4646433132355d5b625d0a2f53504d2d524d0a0a0a5b3837434545425d5b635d5b625dd985d8b9d8b1d981d8a920d8b3d98ad8b1d981d8b120d984d8a7d8b9d8a8203a200a0a5b4646433132355d5b625d0a2f726567696f6e2b31323334353637380a0a0a5b3837434545425d5b635d5b625dd8aad8acd8b3d8b320d8b9d984d98920d8a7d984d8b3d983d988d8a7d8af3a200a0a5b4646433132355d5b625d0a2f53515541442d5350540a0a0a5b3837434545425d5b635d5b625dd8aad8acd8b3d8b320d8b9d984d98920d8a7d984d8b1d988d9853a200a0a5b4646433132355d5b625d0a2f524f4d2d5350590a0a0a5b3837434545425d5b635d5b625d20d8b9d985d98420d984d8a7d8ba20d984d8add8b3d8a7d8a8d9833a200a0a5b4646433132355d5b625d0a2f4c41472d594f550a0a0a5b3837434545425d5b635d5b625dd8a7d984d8add8b5d988d98420d8b9d984d98920d983d988d8af20d8a7d984d8b1d988d9853a200a0a5b4646433132355d5b625d0a2f524f4d2d434f44450a0a0a5b3837434545425d5b635d5b625dd8a5d8b6d8a7d981d8a920d98ad988d8aad98ad988d8a8d8b1d8b23a200a0a5b4646433132355d5b625d0a2f464f582d59540a0a0a5b3837434545425d5b635d5b625dd8a5d8b1d8b3d8a7d98420d8b1d8b3d8a7d8a6d98420d8b3d8a8d8a7d98520d985d8b6d8a7d8afd8a920d984d984d8add8b8d8b13a200a0a5b4646433132355d5b625d0a2f73706d2068696969690a0a0a5b3837434545425d5b635d5b625dd8a5d8b6d8a7d981d8a920353020d8a3d984d98120d8b0d987d8a83a200a0a5b4646433132355d5b625d0a2f474f4c440a0a0a5b3837434545425d5b635d5b625dd8a5d8b6d8a7d981d8a920313020d8a3d984d98120d8a3d984d985d8a7d8b33a200a0a5b4646433132355d5b625d0a2f4449414d0a0a0a5b3837434545425d5b635d5b625dd8a7d984d8b1d982d8b5d8a7d8aa20d985d986203120d8a5d984d9892037303a200a0a5b4646433132355d5b625d0a2f656d6f74657331202d3e3e202f656d6f74657337300a0a0a5b3838326166615d5b635d5b625d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d0a0a0a5b6666666630305d5b635d5b625dd985d8b9d984d988d985d8a7d8aa20d8a5d8b6d8a7d981d98ad8a93a200a0a0a5b6666666630305d5b635d5b625dd8a5d986d8b3d8aad8bad8b1d8a7d9853a205b6661623132615d5b635d5b625d206f6d3170390a0a0a5b6666666630305d5b635d5b625dd8aad984d8bad8b1d8a7d9853a205b6661623132615d5b635d5b625d2040535f44445f460a0a0a5b3838326166615d5b635d5b625d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d0a0a0a5b3233393742355d5b635d5b625dd8a5d8b5d8afd8a7d8b120d8a7d984d8a8d988d8aa3a2056320a0a0a5b3233393742355d5b635d5b625dd8a7d984d985d8b7d988d8b13a20464f580a0a0a5b3233393742355d5b635d5b625dd8aad984d8bad8b1d8a7d9853a200a68747470733a2f2f742e6d652f2b636374785a723239597a59774e325a6b0a0a0a5b3838326166615d5b635d5b625d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d28a083cabd064a250a0b4f5554e385a4414c56494e10e7b290ae0320d20128c1b7f8b103420737526164616121520261726a640a5e68747470733a2f2f6c68332e676f6f676c6575736572636f6e74656e742e636f6d2f612f414367386f634a614d4363556f6c4355397148576c6c2d79506e76516d3354782d304630304d30596a633350437737326f7a44503d7339362d63100118017200"
                                    msg_help_en = f"120000071508{id}101220022a880e08{id}10{id}22e00c0a5b3837434545425d5b635d5b625d435b3030424646465d5b635d5b625d4f5b3145393046465d5b635d5b625d445b3030303046465d5b635d5b625d455b3030303038425d5b635d5b625d58205b3837434545425d5b635d5b625d545b3030424646465d5b635d5b625d455b3145393046465d5b635d5b625d415b3030303046465d5b635d5b625d4d0a5b3830303038305d5b635d5b625d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d0a0a0a5b3233393742355d5b635d5b625d417661696c61626c6520636f6d6d616e647320696e2074686520626f74206172653a200a0a0a5b3837434545425d5b635d5b625d46616b6520467269656e643a200a0a5b4646433132355d5b625d0a2f696431323334353637380a0a0a5b3837434545425d5b635d5b625d5370616d2067726f757020696e7669746174696f6e73207573696e67203a200a0a5b4646433132355d5b625d0a40696e764f4e0a40696e764f46460a0a0a5b3837434545425d5b635d5b625d436f6e7665727420737175616420746f203520706c61796572733a200a0a5b4646433132355d5b625d0a2f35730a0a0a5b3837434545425d5b635d5b625d436f6e7665727420737175616420746f203620706c61796572733a200a0a5b4646433132355d5b625d0a2f36730a0a0a5b3837434545425d5b635d5b625d53515549442d454d4f5445533a200a20200a5b4646433132355d5b625d0a2f53515549442d454d4f5445532f31323334353637382f363730313638373438382f373232393337323932373339322f3534383338353237390a0a0a5b3837434545425d5b635d5b625d5370616d20726f6f6d3a200a0a5b4646433132355d5b625d0a2f53504d2d524d0a0a0a5b3837434545425d5b635d5b625d506c6179657220726567696f6e3a200a0a5b4646433132355d5b625d0a2f726567696f6e2b31323334353637380a0a0a5b3837434545425d5b635d5b625d5351554144205350593a200a0a5b4646433132355d5b625d0a2f53515541442d5350540a0a0a5b3837434545425d5b635d5b625d524f4d205350593a200a0a5b4646433132355d5b625d0a2f524f4d2d5350590a0a0a5b3837434545425d5b635d5b625d4c414720594f5552204143434f554e543a200a0a5b4646433132355d5b625d0a2f4c41472d594f550a0a0a5b3837434545425d5b635d5b625d47657420524f4f4d20434f44453a200a0a5b4646433132355d5b625d0a2f524f4d2d434f44450a0a0a5b3837434545425d5b635d5b625d41646420594f555455424552533a200a0a5b4646433132355d5b625d0a2f464f582d59540a0a0a5b3837434545425d5b635d5b625d5350414d204d45535341474520416e74692062616e6e65643a200a0a5b4646433132355d5b625d0a2f73706d2068696969690a0a0a5b3837434545425d5b635d5b625d4144442035306b20474f4c443a200a0a5b4646433132355d5b625d0a2f474f4c440a0a0a5b3837434545425d5b635d5b625d4144442031304b206469616d6f6e643a200a0a5b4646433132355d5b625d0a2f4449414d0a0a0a5b3837434545425d5b635d5b625d454d4f544531202d2d3e3e20454d4f544537303a200a0a5b4646433132355d5b625d0a2f656d6f74657331202d3e3e202f656d6f74657337300a0a0a5b3838326166615d5b635d5b625d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d0a0a0a5b6666666630305d5b635d5b625d4d4f524520494e464f524d4154494f4e3a200a0a0a5b6666666630305d5b635d5b625d496e7374616772616d3a205b6661623132615d5b635d5b625d206f6d3170390a0a0a5b6666666630305d5b635d5b625d54656c656772616d3a205b6661623132615d5b635d5b625d2040535f44445f460a0a0a5b3838326166615d5b635d5b625d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d0a0a0a5b3233393742355d5b635d5b625d424f542056455253494f4e3a2056320a0a0a5b3233393742355d5b635d5b625d444556454c4f504552204259203a20464f580a0a0a5b3233393742355d5b635d5b625d74656c656772616d203a200a68747470733a2f2f742e6d652f2b636374785a723239597a59774e325a6b0a0a0a5b3838326166615d5b635d5b625d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d28a083cabd064a250a0b4f5554e385a4414c56494e10e7b290ae0320d20128c1b7f8b103420737526164616121520261726a640a5e68747470733a2f2f6c68332e676f6f676c6575736572636f6e74656e742e636f6d2f612f414367386f634a614d4363556f6c4355397148576c6c2d79506e76516d3354782d304630304d30596a633350437737326f7a44503d7339362d63100118017200"
                                    client.send(bytes.fromhex(msg_help_en))
                                    time.sleep(2)
                                    client.send(bytes.fromhex(msg_help_ar))
                                except:
                                    pass
####################################
                elif b"/SQUAD-SPY" in dataS:
                    try:
                        op.send(bytes.fromhex("0503000001d01fb578313150905babcef51dd24ed75fd0a24b024bd1429646114bc22e604afd35a96fbc48710b2d9cfec4378287ec829e33a78608fd2dd138d4d24a19c00fbfdc9f15c77ff86d638b34de95bd886e3075e82d3f4a3888f9b6943463022c43fb90e229f0eaf8a788f6f766d891d99eb2c37b277144923212810b3c80d1c521790154ed270f5241adc136f2a22816e0bc84fcaf79386b27559de966aa788c184d35bbbfaa03a5f08746f8db0e73b2c91ec4515d61f689a0cad30a7cbd6c325151e879dabc43d506b3240abe41bc0d6b4416c18f68ef4af2d04c381be6bf586f6b25727c0c85c03a579137e4a6c602ef6d833dabdab3eba3a5266e5a4731fbfb1720b60f124cd8fd4fa26cc7a9fb6e0a218d8809f57b204d22fa97520aeb99007c7b71c709e53ecc688c9963e0786909152fa93f06dc93085468dae34e1609f33f7dee228fb058c6efd6846b50ac54db0aebb8f5bc2f6751f9e2886dbab41cbaf5a1d8cd88e6c13a2a2a56b613a2d32179dc3f781493a5027322ac0cb1a2d3c79d49fb12ed26230e1561df43d315a27be17b5debdba757803305252b5443f3d77cd319dde9c49a72c636d93d02bdd9597168f378aa6e41d0fd545abf8bc0883f3dac11ea27166683c7111a0f329bf6b6a5"))
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][i][c][7cfc00] - Spy | AntiKick On", 0.2)).start()
                    except:
                        pass
####################################
                elif code_verified and  b"/id" in dataS:
                    try:
                        i = re.split('/id', str(dataS))[1]
                        if '***' in i:
                            i = i.replace('***', '106')
                        id = str(i).split('(\\x')[0]
                        id = Encrypt_ID(id)
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), f"[b][i][c][7cfc00] - Done ADD PLAYER !\n - Enjoy\n - By : CODEX TEAM", 0.2)).start()
                        fake_friend(op, id)
                    except:
                        pass
####################################
                elif code_verified and  b"/ROM-SPY" in dataS:
                    try:
                        op.send(b"\x0e\x15\x00\x00\x00P\xd6\xd5\x19\x00+\xdc\xc6M\xe8\xa4,\x1a\xae\xdf\\:\xaa\xcf|\xe6\x94\xef\xbf\xc1\xf1\x1f\x02h\t\xb6%\xe7\x93aM\xd1?\xfa8\xee\xccUO\xf3 \xa6\x1b\x8a\xc6\x96\x99\xa8\xeb^\xda\xb7;9\xe9\xd9\x10zP\xd5\xe0\x83\xa2\xbc\x8c\x01\xfb\xadd\xdb\xcek\x85\x81\xcdP")
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][i][c][7cfc00] - Spy | AntiKick On", 0.2)).start()
                    except:
                        pass
####################################
                elif b"/LAG-YOU" in dataS:
                    for i in range (99999999999999):
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][FBB117]- ∫   LAGGGGG NEGAAA\n\n/FUCK YOUUㅤㅤ", 1.0)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][FBB117]- ∫ FUCK FUCK FUCK\n\n/FUCK YOUU\n\nFUCK FUCK", 1.0)).start()
                                time.sleep(0.01)
####################################
                elif code_verified and   b"@invON" in dataS and '1200' in dataS.hex()[0:4]:
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), "[B][C][7CFC00] - Spam Invite On ", 0.2)).start()
                        spamm = True
                elif code_verified and   b"@invOFF" in dataS and '1200' in dataS.hex()[0:4]:
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), "[B][C][FF0000] - Spam Invite Off ", 0.2)).start()
                        spamm = False
####################################
                elif code_verified and  b"/6s" in dataS:
                    id = dataS.hex()[12:22]
                    try:
                        op.send(bytes.fromhex(f"050000032708{id}100520082a9a0608dbdcd7cb251a910608{id}12024d4518012005329d0508{id}121ee28094cd9ecd9fcd9ee29885efbcb6efbca5efbcaeefbcafefbcade385a41a024d4520ebdd88b90628363087cbd1303832421880c38566949be061e1cea561b793e66080a89763e5bfce64480150d60158991468b7db8dae037a05ab93c5b00382011f08d1daf1eb0412054f75656973180420d487d4f0042a0808cc9d85f304100392010b0107090a0b12191a1e20229801db01a0014fc00101d001ada48aaf03e80101880203920208c205d628ae2db202aa02050801109c44aa0208080210ea3018c413aa0208080f10d836188827aa0205081710bd33aa0205082b10e432aa0205083910a070aa0205083d10c16faa02050849108439aa0205081810d836aa0205081a10d836aa0205081c10d836aa0205082010d836aa0205082210d836aa0205082110d836aa0205082310d836aa0205083110e432aa0205084110d836aa0205084d10e432aa0205081b10d836aa0205083410d836aa0205082810e432aa0205082910e432c202cd0112041a0201041a730848121301040506070203f1a802f4a802f2a802f3a8021a0b080110031886032086ac021a0b0802100418810420c59a081a0b0803100418da0620ecb4051a06080520f5ec021a0d08f1a802100318b80320def0041a0d08f2a802100318bc0520d0e90a1a0d08f3a802100318ef032092c9051a1208501201631a0b0863100e188f0420eeba0d1a1b0851120265661a09086520a6910128e7021a08086620822d289e05221f121d65ed0e890ed9049103f503ad02f90abd05e907a1068507cd08950ab109d802a6a38daf03ea020410011801f202080885cab5ee01105c8a0300920300980398e0b3af0ba20319efbca334e385a4eaa884e385a4efbcb4efbca5efbca1efbcada80368b00301c2030a081c100f180320052801e203014fea03003a011a403e50056801721e313733303239333438313635343436323834305f6c646a72387477723378880180909beaf3d18fd919a20100b001e201ea010449444331fa011e313733303239333438313635343436363239355f6f747735637831756c6d050000031e08{id}1005203a2a910608{id}12024d4518012005329d0508{id}121ee28094cd9ecd9fcd9ee29885efbcb6efbca5efbcaeefbcafefbcade385a41a024d4520ebdd88b90628363087cbd1303832421880c38566949be061e1cea561b793e66080a89763e5bfce64480150d60158991468b7db8dae037a05ab93c5b00382011f08d1daf1eb0412054f75656973180420d487d4f0042a0808cc9d85f304100392010b0107090a0b12191a1e20229801db01a0014fc00101d001ada48aaf03e80101880203920208c205d628ae2db202aa02050801109c44aa0208080210ea3018c413aa0208080f10d836188827aa0205081710bd33aa0205082b10e432aa0205083910a070aa0205083d10c16faa02050849108439aa0205081810d836aa0205081a10d836aa0205081c10d836aa0205082010d836aa0205082210d836aa0205082110d836aa0205082310d836aa0205083110e432aa0205084110d836aa0205084d10e432aa0205081b10d836aa0205083410d836aa0205082810e432aa0205082910e432c202cd0112041a0201041a730848121301040506070203f1a802f4a802f2a802f3a8021a0b080110031886032086ac021a0b0802100418810420c59a081a0b0803100418da0620ecb4051a06080520f5ec021a0d08f1a802100318b80320def0041a0d08f2a802100318bc0520d0e90a1a0d08f3a802100318ef032092c9051a1208501201631a0b0863100e188f0420eeba0d1a1b0851120265661a09086520a6910128e7021a08086620822d289e05221f121d65ed0e890ed9049103f503ad02f90abd05e907a1068507cd08950ab109d802a6a38daf03ea020410011801f202080885cab5ee01105c8a0300920300980398e0b3af0ba20319efbca334e385a4eaa884e385a4efbcb4efbca5efbca1efbcada80368b00301c2030a081c100f180320052801e203014fea03003a011a403e50056801721e313733303239333438313635343436323834305f6c646a72387477723378880180909beaf3d18fd919a20100b001e201ea010449444331fa011e313733303239333438313635343436363239355f6f747735637831756c6d"))
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][i][c][7cfc00] - 6 In Sqiud On  ! \n - By : CODEX TEAM", 0.2)).start()
                    except:
                        pass
####################################
                elif code_verified and  b"/5s" in dataS:
                    id = dataS.hex()[12:22]
                    try:
                        op.send(bytes.fromhex(f"05000001ff08{id}1005203a2af20308{id}12024d451801200432f70208{id}1209424c52585f4d6f642b1a024d4520d78aa5b40628023085cbd1303832421880c38566fa96e660c19de061d998a36180a89763aab9ce64480150c90158e80792010801090a12191a1e209801c901c00101e801018802039202029603aa0208080110e43218807daa0207080f10e4322001aa0205080210e432aa0205081810e432aa0205081a10e432aa0205081c10e432aa0205082010e432aa0205082210e432aa0205082110e432aa0205081710e432aa0205082310e432aa0205082b10e432aa0205083110e432aa0205083910e432aa0205083d10e432aa0205084110e432aa0205084910e432aa0205084d10e432aa0205081b10e432aa0205083410e432aa0205082810e432aa0205082910e432c2022812041a0201041a0508501201631a060851120265661a0f0848120b0104050607f1a802f4a8022200ea0204100118018a03009203009803b7919db30ba20319c2b27854e19687e197a95fe191ade192aae197a95945e19687e20301523a011a403e50056801721e313732303237323231313638373535353930315f736f3278687a61366e347801820103303b30880180e0aecdacceba8e19a20100b00114ea010449444332fa011e313732303237323231313638373535383330335f71356f79736b3934716d"))
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][i][c][7cfc00] - 5 In Sqiud On  ! \n - By : CODEX TEAM", 0.2)).start()
                    except:
                        pass
####################################
                elif code_verified and b"/spm" in dataS:
                    	Fox = dataC
                    	threading.Thread(target=send_msg, args=(client, dataS.hex(), "[B][C][FF0000] - Spam message on ", 0.2)).start()
                    	for i in range(2):
                            for _ in range(20):
                                remote.send(Fox)
                                time.sleep(0.04)
                                time.sleep(0.2)
####################################
                elif code_verified and  b"/pc" in dataS:
	                 	text = str(bytes.fromhex(dataS.hex()))
	                 	pattern = r'/pc(\d+)'
	                 	match = re.search(pattern, text)
	                 	number = match.group(1)
	                 	id = dataS.hex()[12:22]
	                 	id_admin = "d3858dd223"
	                 	if len(id_admin) > 8:
	                         name = getname(number)
	                         hex_name = name.encode('utf-8').hex()
	                         hex_name = adjust_text_length(hex_name)
	                         try:
	                             op.send(bytes.fromhex(f'05000003ff08{id}100520062af20708{id_admin}12024d451801200332cc0408{id_admin}12135b6564303930395d50454741e2808f535553201a024d4520a6e38baa0628443087cbd13038324218e0f38766e796a3618994e660f39ae061e5b7d064bfb8ce64480150ce01588e0c60f5d7d0ad0368c2dc8dae037a05d7d0cab00382012b08b3daf1eb041211d8b2d98ad988d98ad986d983d983e29cbf180620b687d4f0042a0808c49d85f30410038801ed89c5b00392010b0107090a0b1216191a20239801cd01a00111a80185fff5b103c00101c80101d001bace89af03e80101880203920207c20500a606e532aa020a080110c03e18f0602002aa0205080210b232aa0205080310e432aa020a080f10918a0118a09c01aa0205081710e750aa0205081810b768aa0205081a10da74aa0206081b10918a01aa0206081c10958c01aa02050820108b79aa0205082110eb7aaa0205082210a275aa0206082310dc8701aa0205082b10f476aa0205083110f476aa0206083910918a01aa0206083d10918a01aa0206084110918a01aa0205084910e432aa0205084d10e432aa0206083410918a01aa0205082810e432aa0205082910e432c2022112041a0201041a090848120501040506071a0508501201631a0508511201652200ea02520a4c68747470733a2f2f67726170682e66616365626f6f6b2e636f6d2f76392e302f3237373631373532363237343633352f706963747572653f77696474683d313630266865696768743d31363010011801f202090887cab5ee0110870a8a030808021003180528019203009803f3e78ea30ba20315e298afd986d8a7d8acd988d986d98ae298afe29c9432d00208{id}120b{hex_name}1a024d452096ed8baa0628043089cbd13038324214fa96e660b599a361c19de061aab9ce64abb9ce64480150c90158e80792010601090a1219209801c901c00101c80101e80101880204920206ee07ce010000aa0208080110ff34188064aa020b080f10fd3218b086012001aa0205080210e432aa0205081810fd32aa0205081a10fd32aa0205081c10fd32aa0205082010fd32aa0205082210fd32aa0205082110fd32aa0205081710e432aa0205082310fd32aa0205082b10fd32aa0205083110fd32aa0205083910fd32aa0205083d10fd32aa0205084110fd32aa0205084910d836aa0205084d10e432aa0205081b10fd32aa0205083410fd32aa0205082810e432aa0205082910e432c2022112041a0201041a090848120501040506071a0508501201631a0508511201652200ea0204100118018a03009203003a0101400150016801721e313639383838363035353130343733333939355f6a67386c37333431646688018090aefec3978fef17a20100b001e001ea010449444331'))
	                             threading.Thread(target=send_msg, args=(client, dataS.hex(), f"[b][i][c][7cfc00] - Done Get Logo Pc !\n - Enjoy With Logo Pc\n - By : CODEX TEAM", 0.2)).start()
	                         except:
	                             pass
####################################
                elif code_verified and  b"/GOLD" in dataS:
            	    id = dataS.hex()[12:22]
            	    try:
            	        op.send(bytes.fromhex(f"080000001308{id}100820022a0708a6b10318fa01"))
            	        threading.Thread(target=send_msg, args=(client, dataS.hex(), "[B][C][FF0000] - DONE ADD 50K GOLD ", 0.2)).start()
            	    except:
            	        pass
                elif code_verified and  b"/DIAM" in dataS:
                	id = dataS.hex()[12:22]
                	dor = "080000001608a29b81aa22100820022a0a08e7be0110b24f18c801*"
                	raks = dor.replace('*', id)
                	try:
                	    threading.Thread(target=send_msg, args=(client, dataS.hex(), "[B][C][FF0000] - DONE ADD 10K DIAM ", 0.2)).start()
                	    op.send(bytes.fromhex(raks))
                	except:
                	    pass
####################################
                elif code_verified and  b"/FOX-YT" in dataS:
                    yout1 = b"\x06\x00\x00\x00{\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*o\x08\x81\x80\x83\xb6\x01\x1a)[00ff00]\xd8\xb5\xd8\xa7\xd8\xa6\xd8\xaf\xe3\x85\xa4\xd8\xa7\xd9\x84\xd8\xa8\xd9\x87\xd8\xa7\xd8\xa6\xd9\x85[00ff00]2\x02ME@N\xb0\x01\x13\xb8\x01\xdc)\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\tAO'-'TEAM\xf0\x01\x01\xf8\x01\xdc\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x11\xd8\x02F"
                    yout2 = b'\x06\x00\x00\x00|\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*p\x08\xd6\xd1\xb9(\x1a![00ff00]\xef\xbc\xa8\xef\xbc\xac\xe3\x85\xa4Hassone.[00ff00]2\x02ME@G\xb0\x01\x13\xb8\x01\xcf\x1e\xd8\x01\xcc\xd6\xd0\xad\x03\xe0\x01\xed\xdc\x8d\xae\x03\xea\x01\x1d\xef\xbc\xb4\xef\xbc\xa8\xef\xbc\xa5\xe3\x85\xa4\xef\xbc\xa8\xef\xbc\xa5\xef\xbc\xac\xef\xbc\xac\xe0\xbf\x90\xc2\xb9\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01'
                    yout3 = b'\x06\x00\x00\x00x\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*l\x08\xe9\xa7\xe9\x1b\x1a [00ff00]DS\xe3\x85\xa4WAJIHANO\xe3\x85\xa4[00ff00]2\x02ME@Q\xb0\x01\x14\xb8\x01\xca2\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x10.DICTATORS\xe3\x85\xa4\xe2\x88\x9a\xf0\x01\x01\xf8\x01\xc4\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02+'
                    yout4 = b'\x06\x00\x00\x00z\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*n\x08\xed\xd4\xa7\xa2\x02\x1a\x1f[00ff00]M8N\xe3\x85\xa4y\xe3\x85\xa4Fouad[00ff00]2\x02ME@O\xb0\x01\x13\xb8\x01\xa9#\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xdb\xdb\x8d\xae\x03\xea\x01\x0cGREAT\xe2\x80\xbfWALL\xf0\x01\x01\xf8\x01b\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\r\xd8\x023\xe0\x02\xc1\xb7\xf8\xb1\x03'
                    yout5 = b"\x06\x00\x00\x00\x84\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*x\x08\xb6\xc0\xf1\xcc\x01\x1a'[00ff00]\xd9\x85\xd9\x84\xd9\x83\xd8\xa9*\xd9\x84\xd9\x85\xd8\xb9\xd9\x88\xd9\x82\xd9\x8a\xd9\x86[00ff00]2\x02ME@G\xb0\x01\x05\xb8\x01\x82\x0b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x15\xe9\xbf\x84\xef\xbc\xac\xef\xbc\xaf\xef\xbc\xb2\xef\xbc\xa4\xef\xbc\xb3\xe9\xbf\x84\xf0\x01\x01\xf8\x01>\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x05\xd8\x02\x0e"
                    yout6 = b'\x06\x00\x00\x00\x8e\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x81\x01\x08\xeb\x98\x88\x8e\x01\x1a"[00ff00]OP\xe3\x85\xa4BNL\xe3\x85\xa4\xe2\x9a\xa1\xe3\x85\xa4*[00ff00]2\x02ME@R\xb0\x01\x10\xb8\x01\xce\x16\xd8\x01\x84\xf0\xd2\xad\x03\xe0\x01\xa8\xdb\x8d\xae\x03\xea\x01\x1f\xe1\xb4\x8f\xe1\xb4\xa0\xe1\xb4\x87\xca\x80\xe3\x85\xa4\xe1\xb4\x98\xe1\xb4\x8f\xe1\xb4\xa1\xe1\xb4\x87\xca\x80\xe2\x9a\xa1\xf0\x01\x01\xf8\x01A\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01\xe0\x02\xf3\x94\xf6\xb1\x03'
                    yout7 = b"\x06\x00\x00\x00\x8e\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x81\x01\x08\xb0\xa4\xdb\x80\x01\x1a'[00ff00]\xd9\x85\xd9\x83\xd8\xa7\xd9\x81\xd8\xad\xd8\xa9.\xe2\x84\x93\xca\x99\xe3\x80\xb5..[00ff00]2\x02ME@T\xb0\x01\x13\xb8\x01\xfc$\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xc1\xdb\x8d\xae\x03\xea\x01\x1d\xef\xbc\xad\xef\xbc\xa1\xef\xbc\xa6\xef\xbc\xa9\xef\xbc\xa1\xe3\x85\xa4\xe2\x8e\xb0\xe2\x84\x93\xca\x99\xe2\x8e\xb1\xf0\x01\x01\xf8\x01\xdb\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0f\xd8\x02>"
                    yout8 = b'\x06\x00\x00\x00y\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*m\x08\xfd\x8a\xde\xb4\x02\x1a\x1f[00ff00]ITZ\xe4\xb8\xb6MOHA\xe3\x85\xa42M[00ff00]2\x02ME@C\xb0\x01\n\xb8\x01\xdf\x0f\xd8\x01\xac\xd8\xd0\xad\x03\xe0\x01\xf2\xdc\x8d\xae\x03\xea\x01\x15\xe3\x80\x9dITZ\xe3\x80\x9e\xe1\xb5\x97\xe1\xb5\x89\xe1\xb5\x83\xe1\xb5\x90\xf8\x01\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0e\xd8\x026'
                    yout9 = b'\x06\x00\x00\x00w\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*k\x08\xc6\x99\xddp\x1a\x1b[00ff00]HEROSHIIMA1[00ff00]2\x02ME@I\xb0\x01\x01\xb8\x01\xe8\x07\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1e\xef\xbc\xa8\xef\xbc\xa5\xef\xbc\xb2\xef\xbc\xaf\xef\xbc\xb3\xef\xbc\xa8\xef\xbc\xa9\xef\xbc\xad\xef\xbc\xa1\xef\xa3\xbf\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01'
                    yout10 = b'\x06\x00\x00\x00p\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*d\x08\xde\x91\xb7Q\x1a\x1c[00ff00]SH\xe3\x85\xa4SHIMA|M[00ff00]2\x02ME@R\xb0\x01\x14\xb8\x01\xe7C\xd8\x01\xdd\xd6\xd0\xad\x03\xe0\x01\xca\xdb\x8d\xae\x03\xea\x01\tSH\xe3\x85\xa4Team\xf8\x014\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x11\xd8\x02G\xe0\x02\x89\xa0\xf8\xb1\x03'
                    yout11 = b'\x06\x00\x00\x00h\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\\\x08\xa1\x9f\xb3\xf4\x01\x1a\x1b[00ff00]2JZ\xe3\x85\xa4POWER[00ff00]2\x02ME@M\xb0\x01\x13\xb8\x01\xa5(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xec\xdb\x8d\xae\x03\xf0\x01\x01\xf8\x01\x9a\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02.\xe0\x02\xb2\xe9\xf7\xb1\x03'
                    yout12 = b'\x06\x00\x00\x00\x8f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x82\x01\x08\xaa\xe5\xa4\xe3\x01\x1a-[00ff00]\xe3\x85\xa4\xd8\xb4\xd9\x83\xd8\xa7\xd9\x8e\xd9\x83\xd9\x80\xd9\x8a\xe3\x80\x8e\xe2\x85\xb5\xe1\xb4\x98\xe3\x80\x8f[00ff00]2\x02ME@Q\xb0\x01\x13\xb8\x01\xf2*\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xaf\xdb\x8d\xae\x03\xea\x01\x15\xe2\x80\xa2\xe3\x85\xa4\xe2\x93\x8b\xe2\x92\xbe\xe2\x93\x85\xe3\x85\xa4\xe2\x80\xa2\xf8\x01q\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02e\xe0\x02\xa0\xf1\xf7\xb1\x03'
                    yout13 = b'\x06\x00\x00\x00`\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*T\x08\xd2\xbc\xae\x07\x1a%[00ff00]SYBLUS\xe3\x85\xa4\xe4\xba\x97\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4[00ff00]2\x02ME@E\xb0\x01\x01\xb8\x01\xe8\x07\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01'
                    yout14 = b'\x06\x00\x00\x00\x86\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*z\x08\xfd\x8b\xf4\xfa\x01\x1a$[00ff00]"\xd8\xaf\xd8\xb1\xd8\xa7\xd8\xba\xd9\x88\xd9\x86\xd9\x80\xd9\x88\xd9\x81"[00ff00]2\x02ME@F\xb0\x01\x13\xb8\x01\xec \xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x12\xe1\xb4\x98\xe1\xb4\x84\xe1\xb5\x80\xe1\xb5\x89\xe1\xb5\x83\xe1\xb5\x90\xf0\x01\x01\xf8\x01\xb0\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x04\xd8\x02\t\xe0\x02\xf2\x94\xf6\xb1\x03'
                    yout15 = b'\x06\x00\x00\x00\x7f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*s\x08\x90\xf6\x87\x15\x1a"[00ff00]V4\xe3\x85\xa4RIO\xe3\x85\xa46%\xe3\x85\xa4zt[00ff00]2\x02ME@M\xb0\x01\x13\xb8\x01\x95&\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb1\xdd\x8d\xae\x03\xea\x01\x0e\xe1\xb4\xa0\xe1\xb4\x80\xe1\xb4\x8d\xe1\xb4\x8f\xd1\x95\xf0\x01\x01\xf8\x01\xe2\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02^\xe0\x02\x85\xff\xf5\xb1\x03'
                    yout16 = b'\x06\x00\x00\x00s\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*g\x08\xaa\x84\xc1r\x1a\x1f[00ff00]SA777RAWI\xe3\x85\xa4\xe3\x85\xa4[00ff00]2\x02ME@N\xb0\x01\x13\xb8\x01\xc8\x1b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x0cSA7RAWI\xe3\x85\xa4TM\xf0\x01\x01\xf8\x01\xfe\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\t\xd8\x02 '
                    yout17 = b'\x06\x00\x00\x00y\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*m\x08\xe7\xbf\xb6\x8f\x01\x1a\x1c[00ff00]SVG.NINJA\xe2\xbc\xbd[00ff00]2\x02ME@I\xb0\x01\x13\xb8\x01\x94\x1b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x85\xdb\x8d\xae\x03\xea\x01\x15\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4???\xe3\x85\xa4\xe3\x85\xa4\xf0\x01\x01\xf8\x01o\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x10\xd8\x02?'
                    yout18 = b"\x06\x00\x00\x00\x9d\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x90\x01\x08\xa8\xe8\x91\xd7\x01\x1a.[00ff00]\xef\xbc\xa1\xef\xbc\xac\xef\xbc\x93\xef\xbc\xab\xef\xbc\xa5\xef\xbc\xa4\xe4\xba\x97\xef\xbc\xb9\xef\xbc\xb4\xe3\x85\xa4[00ff00]2\x02ME@N\xb0\x01\x13\xb8\x01\x97'\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1e\xef\xbc\xa1\xef\xbc\xac\xef\xbc\x93\xef\xbc\xab\xef\xbc\xa5\xef\xbc\xa4\xe2\x80\xa2\xef\xbc\xb9\xef\xbc\xb4\xe2\x9c\x93\xf0\x01\x01\xf8\x01\xab\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x10\xd8\x02@\xe0\x02\xe9\x80\xf8\xb1\x03"
                    yout19 = b'\x06\x00\x00\x00r\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*f\x08\x9b\x94\xaa\r\x1a\x1c[00ff00]FARAMAWY_1M.[00ff00]2\x02ME@I\xb0\x01\x01\xb8\x01\xe8\x07\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x12\xe2\x80\xa2\xe3\x85\xa4STRONG\xe3\x85\xa4\xe2\x80\xa2\xf0\x01\x01\xf8\x01X\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01'
                    yout20 = b'\x06\x00\x00\x00p\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*d\x08\xde\x91\xb7Q\x1a\x1c[00ff00]SH\xe3\x85\xa4SHIMA|M[00ff00]2\x02ME@R\xb0\x01\x14\xb8\x01\xe7C\xd8\x01\xdd\xd6\xd0\xad\x03\xe0\x01\xca\xdb\x8d\xae\x03\xea\x01\tSH\xe3\x85\xa4Team\xf8\x014\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x11\xd8\x02G\xe0\x02\x89\xa0\xf8\xb1\x03'
                    yout21 = b'\x06\x00\x00\x00h\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\\\x08\xa1\x9f\xb3\xf4\x01\x1a\x1b[00ff00]2JZ\xe3\x85\xa4POWER[00ff00]2\x02ME@M\xb0\x01\x13\xb8\x01\xa5(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xec\xdb\x8d\xae\x03\xf0\x01\x01\xf8\x01\x9a\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02.\xe0\x02\xb2\xe9\xf7\xb1\x03'
                    yout22 = b'\x06\x00\x00\x00\x8f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x82\x01\x08\xaa\xe5\xa4\xe3\x01\x1a-[00ff00]\xe3\x85\xa4\xd8\xb4\xd9\x83\xd8\xa7\xd9\x8e\xd9\x83\xd9\x80\xd9\x8a\xe3\x80\x8e\xe2\x85\xb5\xe1\xb4\x98\xe3\x80\x8f[00ff00]2\x02ME@Q\xb0\x01\x13\xb8\x01\xf2*\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xaf\xdb\x8d\xae\x03\xea\x01\x15\xe2\x80\xa2\xe3\x85\xa4\xe2\x93\x8b\xe2\x92\xbe\xe2\x93\x85\xe3\x85\xa4\xe2\x80\xa2\xf8\x01q\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02e\xe0\x02\xa0\xf1\xf7\xb1\x03'
                    yout23 = b'\x06\x00\x00\x00\x86\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*z\x08\xfd\x8b\xf4\xfa\x01\x1a$[00ff00]"\xd8\xaf\xd8\xb1\xd8\xa7\xd8\xba\xd9\x88\xd9\x86\xd9\x80\xd9\x88\xd9\x81"[00ff00]2\x02ME@F\xb0\x01\x13\xb8\x01\xec \xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x12\xe1\xb4\x98\xe1\xb4\x84\xe1\xb5\x80\xe1\xb5\x89\xe1\xb5\x83\xe1\xb5\x90\xf0\x01\x01\xf8\x01\xb0\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x04\xd8\x02\t\xe0\x02\xf2\x94\xf6\xb1\x03'
                    yout24 = b'\x06\x00\x00\x00s\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*g\x08\xaa\x84\xc1r\x1a\x1f[00ff00]AH\xe3\x85\xa4\xe3\x85\xa4[00ff00]2\x02ME@N\xb0\x01\x13\xb8\x01\xc8\x1b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x0cSA7RAWI\xe3\x85\xa4TM\xf0\x01\x01\xf8\x01\xfe\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\t\xd8\x02 '
                    yout25 = b'\x06\x00\x00\x00y\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*m\x08\xe7\xbf\xb6\x8f\x01\x1a\x1c[00ff00]SVG.NINJA\xe2\xbc\xbd[00ff00]2\x02ME@I\xb0\x01\x13\xb8\x01\x94\x1b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x85\xdb\x8d\xae\x03\xea\x01\x15\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4???\xe3\x85\xa4\xe3\x85\xa4\xf0\x01\x01\xf8\x01o\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x10\xd8\x02?'
                    yout26 = b"\x06\x00\x00\x00\x9d\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x90\x01\x08\xa8\xe8\x91\xd7\x01\x1a.[00ff00]\xef\xbc\xa1\xef\xbc\xac\xef\xbc\x93\xef\xbc\xab\xef\xbc\xa5\xef\xbc\xa4\xe4\xba\x97\xef\xbc\xb9\xef\xbc\xb4\xe3\x85\xa4[00ff00]2\x02ME@N\xb0\x01\x13\xb8\x01\x97'\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1e\xef\xbc\xa1\xef\xbc\xac\xef\xbc\x93\xef\xbc\xab\xef\xbc\xa5\xef\xbc\xa4\xe2\x80\xa2\xef\xbc\xb9\xef\xbc\xb4\xe2\x9c\x93\xf0\x01\x01\xf8\x01\xab\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x10\xd8\x02@\xe0\x02\xe9\x80\xf8\xb1\x03"
                    yout27 = b'\x06\x00\x00\x00r\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*f\x08\x9b\x94\xaa\r\x1a\x1c[00ff00]FARAMAWY_1M.[00ff00]2\x02ME@I\xb0\x01\x01\xb8\x01\xe8\x07\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x12\xe2\x80\xa2\xe3\x85\xa4STRONG\xe3\x85\xa4\xe2\x80\xa2\xf0\x01\x01\xf8\x01X\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01'
                    yout28 = b"\x06\x00\x00\x00\x82\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*v\x08\xaa\xdd\xf1'\x1a\x1d[00ff00]BM\xe3\x85\xa4ABDOU_YT[00ff00]2\x02ME@G\xb0\x01\x13\xb8\x01\xd4$\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1d\xe2\x80\xa2\xc9\xae\xe1\xb4\x87\xca\x9f\xca\x9f\xe1\xb4\x80\xca\x8d\xe1\xb4\x80\xd2\x93\xc9\xaa\xe1\xb4\x80\xc2\xb0\xf0\x01\x01\xf8\x01\x8e\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x07\xd8\x02\x16"
                    yout29 = b'\x06\x00\x00\x00r\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*f\x08\x9a\xd6\xdcL\x1a-[00ff00]\xe1\xb4\x8d\xcd\xa1\xcd\x9co\xe3\x85\xa4\xef\xbc\xa8\xef\xbc\xa1\xef\xbc\xa6\xef\xbc\xa9\xef\xbc\xa4\xef\xbc\xa9[00ff00]2\x02ME@H\xb0\x01\x01\xb8\x01\xe8\x07\xea\x01\x15\xe1\xb4\x8d\xcd\xa1\xcd\x9co\xc9\xb4\xef\xbd\x93\xe1\xb4\x9b\xe1\xb4\x87\xca\x80\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01'
                    yout30 = b'\x06\x00\x00\x00v\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*j\x08\xb6\x92\xa9\xc8\x01\x1a [00ff00]\xef\xbc\xaa\xef\xbc\xad\xef\xbc\xb2\xe3\x85\xa4200K[00ff00]2\x02ME@R\xb0\x01\x13\xb8\x01\xc3(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\n3KASH-TEAM\xf8\x012\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x06\xd8\x02\x13\xe0\x02\x89\xa0\xf8\xb1\x03'
                    yout31 = b"\x06\x00\x00\x00\x92\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x85\x01\x08\xa2\xd3\xf4\x81\x07\x1a'[00ff00]\xd8\xb3\xd9\x80\xd9\x86\xd9\x80\xd8\xaf\xd8\xb1\xd9\x8a\xd9\x84\xd8\xa71M\xe3\x85\xa4[00ff00]2\x02ME@K\xb0\x01\x13\xb8\x01\xc1 \xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1a\xef\xbc\xad\xef\xbc\xa6\xef\xbc\x95\xef\xbc\xb2\xef\xbc\xa8\xe3\x85\xa4\xe1\xb4\xa0\xc9\xaa\xe1\xb4\x98\xf0\x01\x01\xf8\x01\x8c\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0e\xd8\x024\xe0\x02\x87\xff\xf5\xb1\x03"
                    yout32 = b'\x06\x00\x00\x00\x82\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*v\x08\xc5\xcf\x94\x8b\x02\x1a\x18[00ff00]@EL9YSAR[00ffff]2\x02ME@P\xb0\x01\x13\xb8\x01\x86+\xd8\x01\xa2\xd7\xd0\xad\x03\xe0\x01\x89\xae\x8f\xae\x03\xea\x01\x1d-\xc9\xaa\xe1\xb4\x8d\xe1\xb4\x8d\xe1\xb4\x8f\xca\x80\xe1\xb4\x9b\xe1\xb4\x80\xca\x9fs\xe2\xac\x86\xef\xb8\x8f\xf8\x01j\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x14\xd8\x02\xe2\x02\xe0\x02\x9f\xf1\xf7\xb1\x03'
                    yout33 = b'\x06\x00\x00\x00\x82\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*v\x08\xc5\xcf\x94\x8b\x02\x1a\x18[00ff00]@EL9YSAR[00ffff]2\x02ME@P\xb0\x01\x13\xb8\x01\x86+\xd8\x01\xa2\xd7\xd0\xad\x03\xe0\x01\x89\xae\x8f\xae\x03\xea\x01\x1d-\xc9\xaa\xe1\xb4\x8d\xe1\xb4\x8d\xe1\xb4\x8f\xca\x80\xe1\xb4\x9b\xe1\xb4\x80\xca\x9fs\xe2\xac\x86\xef\xb8\x8f\xf8\x01j\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x14\xd8\x02\xe2\x02\xe0\x02\x9f\xf1\xf7\xb1\x03'
                    yout34 = b'\x06\x00\x00\x00x\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*l\x08\xa9\x81\xe6^\x1a\x1e[ffff00]GRINGO\xe3\x85\xa4CRONA[00ff00]2\x02ME@J\xb0\x01\x13\xb8\x01\xd8$\xd8\x01\xd8\xd6\xd0\xad\x03\xe0\x01\x92\xdb\x8d\xae\x03\xea\x01\x12\xe2\x80\xa2\xe3\x85\xa4STRONG\xe3\x85\xa4\xe2\x80\xa2\xf0\x01\x01\xf8\x01q\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x14\xd8\x02\xbc\x01'
                    yout35 = b'\x06\x00\x00\x00\x7f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*s\x08\xeb\x8d\x97\xec\x01\x1a&[00ff00]\xd8\xb9\xd9\x80\xd9\x85\xd9\x80\xd8\xaf\xd9\x86\xd9\x8a\xd9\x80\xd8\xaa\xd9\x80\xd9\x88[00ff00]2\x02ME@F\xb0\x01\x13\xb8\x01\xd3\x1a\xd8\x01\xaf\xd7\xd0\xad\x03\xe0\x01\xf4\xdc\x8d\xae\x03\xea\x01\rOSIRIS\xe3\x85\xa4MASR\xf8\x01o\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02\\\xe0\x02\xf4\x94\xf6\xb1\x03'
                    yout36 = b'\x06\x00\x00\x00\x7f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*s\x08\xb4\xff\xa3\xef\x01\x1a\x1c[00ff00]ZAIN_YT_500K[00ffff]2\x02ME@K\xb0\x01\x13\xb8\x01\xa3#\xd8\x01\xa2\xd7\xd0\xad\x03\xe0\x01\xbb\xdb\x8d\xae\x03\xea\x01\x1b\xe1\xb6\xbb\xe1\xb5\x83\xe1\xb6\xa4\xe1\xb6\xb0\xe3\x85\xa4\xe1\xb5\x97\xe1\xb5\x89\xe1\xb5\x83\xe1\xb5\x90\xf0\x01\x01\xf8\x01\\\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0b\xd8\x02('
                    yout37 = b'\x06\x00\x00\x00\x8f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x82\x01\x08\x86\xa7\x9e\xa7\x0b\x1a([00ff00]\xe2\x80\x94\xcd\x9e\xcd\x9f\xcd\x9e\xe2\x98\x85\xef\xbc\xa2\xef\xbc\xac\xef\xbc\xb2\xef\xbc\xb8[00ff00]2\x02ME@d\xb0\x01\x13\xb8\x01\xe3\x1c\xe0\x01\xf2\x83\x90\xae\x03\xea\x01!\xe3\x85\xa4\xef\xbc\xa2\xef\xbc\xac\xef\xbc\xb2\xef\xbc\xb8\xe3\x85\xa4\xef\xbc\xb4\xef\xbc\xa5\xef\xbc\xa1\xef\xbc\xad\xe3\x85\xa4\xf8\x01u\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02Y\xe0\x02\xc1\xb7\xf8\xb1\x03'
                    yout38 = b'\x06\x00\x00\x00\x85\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*y\x08\xc3\xcf\xe5H\x1a([00ff00]\xe3\x85\xa4BEE\xe2\x9c\xbfSTO\xe3\x85\xa4\xe1\xb5\x80\xe1\xb4\xb5\xe1\xb4\xb7[00ff00]2\x02ME@Q\xb0\x01\x14\xb8\x01\xffP\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xc1\xdb\x8d\xae\x03\xea\x01\x15TIK\xe2\x9c\xbfTOK\xe1\xb5\x80\xe1\xb4\xb1\xe1\xb4\xac\xe1\xb4\xb9\xf0\x01\x01\xf8\x01\xc8\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02q'
                    yout39 = b'\x06\x00\x00\x00\x94\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x87\x01\x08\x97\xd5\x9a.\x1a%[00ff00]\xd8\xb9\xd9\x86\xd9\x83\xd9\x88\xd8\xb4\xe1\xb4\x80\xc9\xb4\xe1\xb4\x8b\xe3\x85\xa4[00ff00]2\x02ME@P\xb0\x01\x13\xb8\x01\xe8(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1f\xe1\xb4\x80\xc9\xb4\xe1\xb4\x8b\xe1\xb4\x9c\xea\x9c\xb1\xca\x9c\xe3\x85\xa4\xe1\xb4\x9b\xe1\xb4\x87\xe1\xb4\x80\xe1\xb4\x8d\xf0\x01\x01\xf8\x01\xb6\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\n\xd8\x02"\xe0\x02\xf2\x94\xf6\xb1\x03'
                    yout40 = b'\x06\x00\x00\x00\x8a\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*~\x08\xf7\xdf\xda\\\x1a/[00ff00]\xef\xbc\xa1\xef\xbc\xac\xef\xbc\xa8\xef\xbc\xaf\xef\xbc\xad\xef\xbc\xb3\xef\xbc\xa9_\xef\xbc\xb9\xef\xbc\xb4\xe2\x9c\x93[00ff00]2\x02ME@P\xb0\x01\x13\xb8\x01\xb9*\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xc1\xdb\x8d\xae\x03\xea\x01\x0cALHOMSI~TEAM\xf0\x01\x01\xf8\x01\x8e\x0e\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02S\xe0\x02\xc3\xb7\xf8\xb1\x03'
                    yout41 = b'\x06\x00\x00\x00\x86\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*z\x08\xb5\xdd\xec\x8e\x01\x1a%[00ff00]\xd8\xa7\xd9\x88\xd9\x81\xe3\x80\x80\xd9\x85\xd9\x86\xd9\x83\xe3\x85\xa4\xe2\x9c\x93[00ff00]2\x02ME@K\xb0\x01\x13\xb8\x01\xdd#\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x18\xef\xbc\xaf\xef\xbc\xa6\xe3\x85\xa4\xef\xbc\xb4\xef\xbc\xa5\xef\xbc\xa1\xef\xbc\xad\xe3\x85\xa4\xf0\x01\x01\xf8\x01\xe8\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02Q'
                    yout42 = b'\x06\x00\x00\x00\x8b\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x7f\x08\x81\xf4\xba\xf8\x01\x1a%[00ff00]\xef\xbc\xa7\xef\xbc\xa2\xe3\x85\xa4\xef\xbc\xae\xef\xbc\xaf\xef\xbc\x91\xe3\x81\x95[00ff00]2\x02ME@N\xb0\x01\x0c\xb8\x01\xbd\x11\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb1\xdd\x8d\xae\x03\xea\x01\x1a\xef\xbc\xa7\xef\xbc\xb2\xef\xbc\xa5\xef\xbc\xa1\xef\xbc\xb4__\xef\xbc\xa2\xef\xbc\xaf\xef\xbc\xb9\xf8\x018\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02-\xe0\x02\x85\xff\xf5\xb1\x03'
                    yout43 = b'\x06\x00\x00\x00o\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*c\x08\xfb\x9d\xb9\xae\x06\x1a\x1c[00ff00]BT\xe3\x85\xa4BadroTV[00ff00]2\x02ME@@\xb0\x01\x13\xb8\x01\xe7\x1c\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x91\xdb\x8d\xae\x03\xea\x01\nBadro_TV_F\xf0\x01\x01\xf8\x01\x91\x1a\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\n\xd8\x02!'
                    yout44 = b"\x06\x00\x00\x00s\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*g\x08\xc4\xe5\xe1>\x1a'[00ff00]\xd8\xb5\xd8\xa7\xd8\xa6\xd8\xaf~\xd8\xa7\xd9\x84\xd8\xba\xd9\x86\xd8\xa7\xd8\xa6\xd9\x85[00ff00]2\x02ME@J\xb0\x01\x14\xb8\x01\xceP\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x03Z7F\xf0\x01\x01\xf8\x01\xd0\x19\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x14\xd8\x02\x9c\x01"
                    yout45 = b'\x06\x00\x00\x00\x85\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*y\x08\xfd\xa4\xa6i\x1a$[00ff00]\xd8\xb2\xd9\x8a\xd9\x80\xd8\xb1\xc9\xb4\xcc\xb67\xcc\xb6\xca\x80\xe3\x85\xa4[00ff00]2\x02ME@M\xb0\x01\x13\xb8\x01\xe1(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x19\xc2\xb7\xe3\x85\xa4\xe3\x85\xa4N\xe3\x85\xa47\xe3\x85\xa4R\xe3\x85\xa4\xe3\x85\xa4\xc2\xb7\xf0\x01\x01\xf8\x01\x8f\t\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02k'
                    yout46 = b'\x06\x00\x00\x00y\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*m\x08\xcc\xb9\xcc\xd4\x06\x1a"[00ff00]\xd8\xa8\xd9\x88\xd8\xad\xd8\xa7\xd9\x83\xd9\x80\xd9\x80\xd9\x80\xd9\x85[00ff00]2\x02ME@9\xb0\x01\x07\xb8\x01\xca\x0c\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x11*\xef\xbc\x97\xef\xbc\xaf\xef\xbc\xab\xef\xbc\xa1\xef\xbc\xad*\xf0\x01\x01\xf8\x01\xad\x05\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01'
                    yout47 = b'\x06\x00\x00\x00e\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*Y\x08\xe8\xbd\xc9b\x1a [00ff00]\xe3\x80\x8cvip\xe3\x80\x8dDR999FF[00ff00]2\x02ME@Q\xb0\x01\x10\xb8\x01\x94\x16\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xf0\x01\x01\xf8\x01\xa0\x04\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02+'
                    yout48 = b'\x06\x00\x00\x00\x82\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*v\x08\x86\xb7\x84\xf1\x01\x1a&[00ff00]\xd8\xa2\xd9\x86\xd9\x8a\xd9\x80\xd9\x80\xd9\x84\xd8\xa7\xce\x92\xe2\x92\x91\xe3\x85\xa4[00ff00]2\x02ME@Q\xb0\x01\x13\xb8\x01\x82)\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x13\xce\x92\xe2\x92\x91\xe3\x85\xa4MAFIA\xe3\x85\xa4\xef\xa3\xbf\xf0\x01\x01\xf8\x01\x95\x04\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02W'
                    yout49 = b'\x06\x00\x00\x00u\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*i\x08\xb4\xbe\xde\x83\x02\x1a [00ff00]SPONGEBOB!\xe3\x85\xa4\xe4\xba\x97[00ff00]2\x02ME@N\xb0\x01\x14\xb8\x01\x842\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x96\xdb\x8d\xae\x03\xea\x01\x0cALHOMSI~TEAM\xf0\x01\x01\xf8\x01\xbd\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02{'
                    yout50 = b'\x06\x00\x00\x00u\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*i\x08\xb4\xbe\xde\x83\x02\x1a [00ff00]SPONGEBOB!\xe3\x85\xa4\xe4\xba\x97[00ff00]2\x02ME@N\xb0\x01\x14\xb8\x01\x842\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x96\xdb\x8d\xae\x03\xea\x01\x0cALHOMSI~TEAM\xf0\x01\x01\xf8\x01\xbd\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02{'
                    yout51 = b'\x06\x00\x00\x00v\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*j\x08\xb8\xa6\x85\xc5\x01\x1a\x1b[00ff00]DARBKA\xe3\x85\xa41M[00ff00]2\x02ME@Q\xb0\x01\x13\xb8\x01\x90(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x12LAST\xe2\x80\x8f\xe3\x85\xa4POWER\xe2\x9a\xa1\xf0\x01\x01\xf8\x01\x92\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02W'
                    try:
                        op.send(yout1)
                        time.sleep(0.05)
                        op.send(yout2)
                        time.sleep(0.05)
                        op.send(yout3)
                        time.sleep(0.05)
                        op.send(yout4)
                        time.sleep(0.05)
                        op.send(yout5)
                        time.sleep(0.05)
                        op.send(yout6)
                        time.sleep(0.05)
                        time.sleep(0.5)
                        op.send(yout7)
                        time.sleep(0.5)
                        op.send(yout8)
                        time.sleep(0.5)
                        op.send(yout9)
                        time.sleep(0.5)
                        op.send(yout10)
                        time.sleep(0.5)
                        op.send(yout11)
                        time.sleep(0.5)
                        op.send(yout12)
                        time.sleep(0.5)
                        op.send(yout13)
                        time.sleep(0.5)
                        op.send(yout14)
                        time.sleep(0.5)
                        op.send(yout15)
                        time.sleep(0.5)
                        op.send(yout16)
                        time.sleep(0.5)
                        op.send(yout17)
                        time.sleep(0.5)
                        op.send(yout18)
                        op.send(yout19)
                        op.send(yout20)
                        op.send(yout21)
                        time.sleep(0.05)
                        op.send(yout22)
                        op.send(yout23)
                        op.send(yout24)
                        op.send(yout25)
                        time.sleep(0.05)
                        op.send(yout26)
                        op.send(yout28)
                        op.send(yout29)
                        op.send(yout30)
                        op.send(yout31)
                        op.send(yout32)
                        time.sleep(0.05)
                        op.send(yout33)
                        op.send(yout34)
                        time.sleep(0.05)
                        op.send(yout35)
                        op.send(yout36)
                        op.send(yout37)
                        op.send(yout38)
                        op.send(yout39)
                        op.send(yout40)
                        time.sleep(0.05)
                        op.send(yout41)
                        op.send(yout42)
                        op.send(yout43)
                        op.send(yout44)
                        op.send(yout45)
                        op.send(yout46)
                        time.sleep(0.05)
                        op.send(yout47)
                        time.sleep(0.5)
                        op.send(yout48)
                        op.send(yout49)
                        time.sleep(0.05)
                        op.send(yout50)
                        op.send(yout51)
                        time.sleep(1)
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][i][c][7cfc00] - Done Add Yutubers In Your List Freinds !\n - Enjoy ! \n - By : CODEX TEAM", 0.2)).start()
                    except:
                        pass
####################################
                if client.send(dataS) <= 0:
                    print("Failed to send data to client.")
                    break
    except Exception as e:
        print(f"ERROR IN exchange_loop: {e}")
#############START BOT###############
def run(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
        s.bind((host, port))
        s.listen()
        print(f"Proxy running on ⟩⟩ : {host},{port}")
        print("DEV BY: FOX")
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn,))
            t.start()
    except Exception as e:
        print(f"ERROR IN run: {e}")
if __name__ == "__main__":
    run("127.0.0.1", )