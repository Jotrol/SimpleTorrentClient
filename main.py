import os
import hashlib
import requests
import random
import socket
import math
import time
import threading

def BDecode(data: bytes):
    offset = 0      # global iterator for data
    def parseInt():
        nonlocal offset
        offset += 1
        end_pos = data.find(b'e', offset)
        integer = int(data[offset : end_pos])
        offset = end_pos + 1
        return integer
    def parseString():
        nonlocal offset
        end_len = data.find(b':', offset)
        str_len = int(data[offset : end_len])
        end_pos = end_len + str_len + 1
        string = data[end_len + 1 : end_pos]
        offset = end_pos
        return string
    def parseList():
        nonlocal offset
        offset += 1
        values = []
        while offset < len(data):
            if data[offset] == ord("e"):
                offset += 1
                return values
            else:
                values.append(parse())
        raise ValueError("Unexpected EOF, expected list contents")
    def parseDict():
        nonlocal offset
        offset += 1
        values = {}
        while offset < len(data):
            if data[offset] == ord('e'):
                offset += 1
                return values
            else:
                key, val = parse(), parse()
                values[key] = val
        raise ValueError("Unexpected EOF, expected dict contents")
    def parse():
        nonlocal offset
        if data[offset] == ord('i'):
            return parseInt()
        elif data[offset] == ord('l'):
            return parseList()
        elif data[offset] == ord('d'):
            return parseDict()
        elif data[offset] in b'0123456789':
            return parseString()
        raise ValueError('Unknown type specifiers: {}'.format(chr(data[offset])))
    result = parse()
    if offset != len(data):
        raise ValueError("Expected EOF, got {} bytes left".format(len(data) - offset))
    return result
def BEncode(data):
    result = b''
    if isinstance(data, str):
        result += str(len(data)).encode() + b':' + data.encode()
    elif isinstance(data, bytes):
        result += str(len(data)).encode() + b':' + data
    elif isinstance(data, int):
        result += b'i' + str(data).encode() + b'e'
    elif isinstance(data, list):
        result += b'l'
        for val in data:
            result += BEncode(val)
        result += b'e'
    elif isinstance(data, dict):
        result += b'd'
        for key in sorted(data.keys()):
            result += BEncode(key)
            result += BEncode(data[key])
        result += b'e'
    else:
        raise ValueError("bencode only supports bytes, int, list and dict")
    return result
def bitarray(input: bytes):
    bits = []
    for bit in input:
        for i in range(0, 8):
            bits.append( True if ((bit >> (7 - i)) & 1) else False)
    return bits


PORT = 6681
BLOCK_SIZE = 2 ** 14
DOWNLOADED = 0

def pick_a_file():
    files = []
    for _file in os.listdir():
        if _file.endswith('.torrent'):
            files.append(_file)

    for e, _file in enumerate(files):
        print("{}. {}".format(e + 1, _file))

    choose = int(input("\nВыберите файл: "))
    os.system("cls")
    try:
        return files[choose - 1]
    except Exception as e:
        print(e)
        return None

def get_trackers(torrent: dict):
    tracker_list = []
    tracker_list.append(torrent[b'announce'].decode())
    try:
        for tracker in torrent[b'announce-list']:
            tracker_list.append(tracker[0].decode())
    except:
        pass
    return tracker_list

def get_peers_from_tracker(file_name: str, tracker_list: list, info_hash: bytes, peer_id: str, uploaded: int, left: int):
    import struct
    from urllib.parse import urlparse, urlencode

    def get_peers_http(tracker, info_hash: bytes, peer_id: str, uploaded: int, left: int):
        params = {
            "info_hash" : info_hash,
            "uploaded"  : uploaded,
            "downloaded": DOWNLOADED,
            "left"      : left,
            "peer_id"   : peer_id,
            "port"      : PORT,
            "compact"   : 1
        }

        try:
            res = requests.get(tracker, params=params)
            if res.status_code == 200:
                raw_peers = BDecode(res.content)[b'peers']  # next - parse ips
                offset = 0
                while offset < len(raw_peers):
                    ip = socket.inet_ntoa(raw_peers[offset : offset + 4])
                    port = int.from_bytes(raw_peers[offset + 4: offset + 6], byteorder="big")
                    peers.append(tuple([ip, port]))
                    offset += 6
        except Exception as e:
            print(e)
    def get_peers_udp_ipv4(conn, info_hash: bytes, peer_id: str, uploaded: int, left: int):
        
        PORT = 6881     # port for socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(15)

        connect_transaction_id = random.randint(0, 100000)      # randomize transaction_id to attempt to connect
        sock.sendto(struct.pack("!QII", 0x41727101980, 0, connect_transaction_id), conn)        # send a request to connect
        try:
            data = sock.recv(512)

            if len(data) == 16:
                action = int.from_bytes(data[0:4], byteorder="big")         # action type of responce
                check_trans = int.from_bytes(data[4:8], byteorder="big")    # returned transaction_id just to make sure, that responce is for us

                if action == 0 and connect_transaction_id == check_trans:
                    connection_id = data[8:16]                         # connection_id that tracker gave to identify us
                    announce_trans_id = random.randint(0, 100000)

                    p_action = struct.pack('!I', 1)                    # announce
                    p_trans_id = struct.pack("!I", announce_trans_id)  # random value used for identification

                    p_downloaded = struct.pack('!Q', DOWNLOADED)       # size of downloaded data
                    p_left = struct.pack("!Q", left)                   # size of left data
                    p_uploaded = struct.pack("!Q", uploaded)           # size of uploaded data

                    event = struct.pack("!I", 0)                       # type of event, 0: none, 1: completed, 2: started, 3: stopped 
                    ip = struct.pack("!I", 0)                          # 0 - default
                    key = struct.pack("!I", 0)                         # idk
                    num_what = struct.pack("!i", -1)                   # -1 - default; used to get n peers
                    port = struct.pack("!h", PORT)                     # port used for peer to download

                    # announce should be binary data; Note that peer_id is str, so we need to encode it
                    announce = connection_id + p_action + p_trans_id + info_hash + peer_id.encode() + p_downloaded + p_left + p_uploaded + event + ip + key + num_what + port

                    sock.sendto(announce, conn)
                    data = sock.recv(2048)

                    action = int.from_bytes(data[0:4], byteorder="big")
                    check_trans = int.from_bytes(data[4:8], byteorder="big")
                    if action == 1 and check_trans == announce_trans_id:
                        sock.close()

                        # parse ips
                        offset = 20
                        while offset < len(data):
                            peers.append(tuple([socket.inet_ntoa(data[offset : offset + 4]), int.from_bytes(data[offset + 4 : offset + 6], byteorder="big")]))
                            offset += 6
            sock.close()
        except Exception as e:
            print("Exception {}".format(e))
            sock.close()
    def show_progress_connecting_to_peers():
        stop = False
        up = False
        while not stop:
            stop = True
            for thread in thread_lsit:
                if thread.is_alive():
                    stop = False
            if stop: 
                break

            show_info(file_name, peers, left)
            print("Получаем пиры.... {}".format('\\' if up else '/' ))
            up = not up
            time.sleep(0.2)

    peers = []
    thread_lsit = []

    for tracker in tracker_list:
        if tracker.startswith("http"):
            thread_lsit.append(threading.Thread(target=get_peers_http, args=(tracker, info_hash, peer_id, uploaded, left)))
        elif tracker.startswith('udp'):
            try:
                parsed_tracker = urlparse(tracker)
                conn = (socket.gethostbyname(parsed_tracker.hostname), parsed_tracker.port) # extract host name and convert it to ip; grab port from url
                thread_lsit.append(threading.Thread(target=get_peers_udp_ipv4, args=(conn, info_hash, peer_id, uploaded, left)))
            except socket.gaierror:
                print('Address extraction problem')

    t = threading.Thread(target=show_progress_connecting_to_peers, args=())

    for thread in thread_lsit:
        thread.start()
    t.start()
    t.join()
    
    peers = [ v for i, v in enumerate(peers) if v not in peers[:i] ]    # удаление повторяющихся ip-адресов
    return peers

def connect_to_peers(file_name, peers: list, full):
    connected = []
    new_peers = []

    thread_list = []

    def try_to_connect(peer: tuple):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        try:
            sock.connect(peer)
            connected.append(sock)
            new_peers.append(peer)  # обновляем список пиров
        except:
            sock.close()

    for peer in peers:
        thread_list.append(threading.Thread(target=try_to_connect, args=(peer, )))
    
    for thread in thread_list:
        thread.start()

    # цикл, который активен, пока хотя бы один поток работает
    up = False
    stop = False
    while not stop:
        stop = True
        for thread in thread_list:
            if thread.is_alive():
                stop = False
        if stop: 
            break
        show_info(file_name, new_peers, full)
        print("Соединяемся с пирами.... {}".format('\\' if up else '/'))
        up = not up
        time.sleep(0.2)
        
    return connected, new_peers

def init_file(file_name):
    with open(file_name, "rb") as f:
        metainfo = f.read()
        torrent = BDecode(metainfo)
        info_hash = hashlib.sha1(BEncode(torrent[b'info'])).digest()
        f.close()

    out = {
             "name" : torrent[b'info'][b'name'].decode(),
             "left" : torrent[b'info'][b'length'],
             "peer-id" : "-PY0001-" + "".join([str(random.randint(0, 9)) for _ in range(0, 12)]),
             "info-hash" : info_hash,
             "tracker-list": get_trackers(torrent),
             "piece-len" : torrent[b'info'][b'piece length'],
             "pieces" : torrent[b'info'][b'pieces']
            }

    return out


def handle_message(file_name, peers, peer, piece_len, num_blocks, full_len, piece_hashes):    
    global DOWNLOADED

    def sendRequest():
        request = b'\x00\x00\x00\x0d\x06' + index.to_bytes(4, byteorder="big") + offset.to_bytes(4, byteorder="big")
        if offset // BLOCK_SIZE == num_blocks - 1:
            request += (piece_len - (num_blocks - 1) * BLOCK_SIZE).to_bytes(4, byteorder="big")
        else:
            request += BLOCK_SIZE.to_bytes(4, byteorder="big")
            
        try:
            peer.send(request)
        except:
            pass
    def send_interested():
        interesed_msg = b'\x00\x00\x00\x01\x02'
        peer.send(interesed_msg)

    offset = 0
    index = 0

    f = open(file_name, 'wb')

    bitfield = []
    block_tracker = [False] * num_blocks

    print("Socket connected on {}".format(peer.getsockname()))

    # recieve first message after handshake - it's gotta be bitfield message
    try:
        data = peer.recv(1024)
        bitfield = bitarray(data)[: math.ceil(full_len/piece_len)]  # calculating actual count of pieces and round it to up
        if all(bitfield):
            print("Found Seeder!")
    except:
        pass

    send_interested()           # for start exchanging information
    while True:
        data = peer.recv(4)

        size = int.from_bytes(data, byteorder="big")

        if size == 0:
            print("Keep alive message get")

            sendRequest()
        elif size == 1:
            data = peer.recv(1)

            msg_id = int.from_bytes(data, byteorder="big")

            if msg_id == 0:
                print("Now you choke")
                f.close()
                peer.close()
                break

            elif msg_id == 1:
                print("Congratulations, you Unchoked")
                sendRequest()
            elif msg_id == 2:
                print("A peer interested in you")
            elif msg_id == 3:
                print("A peer no longer interested in you")
        elif size == 3:
            data = peer.recv(1)

            msg_id = int.from_bytes(data, byteorder="big")

            if msg_id == 9:
                print("Got a port message")
        elif size == 5:
            data = peer.recv(1)

            msg_id = int.from_bytes(data, byteorder="big")

            if msg_id == 4:
                print("Got Have message")
                data = peer.recv(4)

                piece_index = int.from_bytes(data, byteorder="big")

                bitfield[piece_index] = True

                print("Peer got {} piece".format(piece_index))

        elif size == 13:
            data = peer.recv(1)

            msg_id = int.from_bytes(data, byteorder="big")

            if msg_id == 6:
                print("Request message got from Peer")

                raw_index = peer.recv(4)
                raw_begin = peer.recv(4)
                raw_len = peer.recv(4)

                index = int.from_bytes(raw_index, byteorder="big")
                begin = int.from_bytes(raw_begin, byteorder="big")
                length = int.from_bytes(raw_len, byteorder="big")

                print("Request message:\n\tindex: {}\n\tbegin: {}\n\tlen: {}".format(index, begin, length))
            elif msg_id == 8:
                print("Cancel message got from Peer")

                raw_index = peer.recv(4)
                raw_begin = peer.recv(4)
                raw_len = peer.recv(4)

                index = int.from_bytes(raw_index, byteorder="big")
                begin = int.from_bytes(raw_begin, byteorder="big")
                length = int.from_bytes(raw_len, byteorder="big")

                print("Cancel message:\n\tindex: {}\n\tbegin: {}\n\tlen: {}".format(index, begin, length))

        elif size == BLOCK_SIZE or size == BLOCK_SIZE + 9:
            data = peer.recv(1)

            msg_id = int.from_bytes(data, byteorder="big")

            if msg_id == 7:
                print("Piece get")
                raw_index = peer.recv(4)
                raw_offset = peer.recv(4)

                p_index = int.from_bytes(raw_index, byteorder="big")
                p_offset = int.from_bytes(raw_offset, byteorder="big")

                if p_offset == offset and p_index == index:

                    block = b''

                    while len(block) < BLOCK_SIZE:
                        data = peer.recv(1)
                        block += data

                    block_index = offset // BLOCK_SIZE

                    block_tracker[block_index] = block
                    offset += BLOCK_SIZE
                    DOWNLOADED += BLOCK_SIZE

                    if offset >= piece_len:
                        piece = b''.join(_ for _ in block_tracker)
                        
                        if hashlib.sha1(piece).digest() == piece_hashes[index]:
                            f.write(piece)
                            index += 1
                        
                        block_tracker = [False] * num_blocks
                        offset = 0

                    if index == len(pieces_hashes):
                        f.close()
                        peer.close()
                        break

                    sendRequest()
                    show_info(file_name, peers, full_len)
                else:
                    print("Wrong offfset")
                    peer.recv(BLOCK_SIZE) # skip wrong block

                    sendRequest()
        else:
            peer.recv(BLOCK_SIZE)
            sendRequest()

def handshake_with_peer(info_hash: bytes, peer_id: str, peer):
    handshake_msg = b'\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00' + info_hash + peer_id.encode()
    peer.send(handshake_msg)
    data = peer.recv(1024)
    if data:
        _hash = data[28:48]
        if info_hash == _hash:
            return True
    return False

def show_info(file_name, peers, full):
    os.system("cls")
    PROMT_WIDTH = 69
    print("Название торрент-файла: {}".format(file_name))
    print("Пиров: {}".format(len(peers)))
    for peer in peers:
        print("\t{}:{}".format(peer[0], peer[1]))
    print("\nСкачано {} из {} байт".format(DOWNLOADED, full))
    print("Прогресс загрузки:")
    print( (''.join( '#' for _ in range(math.floor(DOWNLOADED / full * PROMT_WIDTH)))), " {:.4f} %".format(DOWNLOADED / full * 100))

if __name__ == "__main__":
    file_name = pick_a_file()
    file_map = init_file(file_name)
    
    torrent_name = file_map["name"]
    uploaded = 0
    full_len, left = file_map["left"], file_map["left"]
    peer_id = file_map["peer-id"]
    info_hash = file_map["info-hash"]
    tracker_list = file_map["tracker-list"]
    piece_len = file_map['piece-len']

    pieces = [False] * math.ceil(float(left) / piece_len)
    pieces_hashes = [ file_map["pieces"][i : i + 20] for i in range(0, len(file_map["pieces"]), 20)]   # хэши каждого куска

    num_blocks = math.ceil(float(piece_len) / BLOCK_SIZE)
    blocks = [False] * num_blocks

    peers = []
    connected = [] # сокеты, которые смогли соединиться с пирами

    # Начальное окно сразу после начала загрузки
    show_info(torrent_name, peers, full_len)
    print("Получаем пиры.....")

    # Получение пиров
    peers = get_peers_from_tracker(torrent_name, tracker_list, info_hash, peer_id, uploaded, left)
    show_info(torrent_name, peers, full_len)

    # Соединяемся с пирами
    connected, peers = connect_to_peers(torrent_name, peers, full_len)
    show_info(torrent_name, peers, full_len)
    print("Соединены с {} пирами".format(len(connected)))
    
    # Рукопажатие
    for peer in connected:
        handshaked = handshake_with_peer(info_hash, peer_id, peer)
        if handshaked:
            handle_message(torrent_name, peers, peer, piece_len, num_blocks, full_len, pieces_hashes)
        else:
            peer.close()

    input()