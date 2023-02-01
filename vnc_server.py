import binascii
import socket
import time
import traceback

import pyDes
from _thread import *
import threading
VERSION = b"RFB 003.008\n"
CHALLENGE = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
port = 5900

def reverse_password(password):
    res = ""
    for i in password:
        hexstring = i.encode().hex()
        binarystring = bin(int(hexstring, 16))[2:].zfill(8)
        revbin = binarystring[::-1]
        revhex = f'{int(revbin, 2):x}'
        res += revhex
    return res

def handle_client_auth(conn, addr):
    conn.send(CHALLENGE)
    response = conn.recv(16)
    hash = ''.join('%02x' % c for c in response)
    print("Auth response",response, hash)

    password = "12345678"
    reversed = reverse_password(password)
    print(reversed)
    des = pyDes.des(bytes.fromhex(reversed.strip()))
    e = des.encrypt(CHALLENGE)
    correct_hash = binascii.hexlify(e).decode()
    print("correct hash ",correct_hash)
    if hash == correct_hash:
        print("Authentication success")
        conn.send(b"\x00\x00\x00\x00")
        print("share desktop flag")
        flag = conn.recv(1)
        print(flag)
        if flag == b'\x01':
            print("client sent share desktop flag: True")
        # send framebuffer parameters
        data = b"\x07\x80\x04\x38\x20\x18\x00\x01\x00\xff\x00\xff\x00\xff\x10\x08\x00\x00\x00\x00\x00\x00\x00\x01\x61"
        conn.send(data)
        msg = conn.recv(24)
        # client encoding data
        print(msg)

        msg = conn.recv(24)
        # client pixel format
        print(msg)

        return True
    else:
        print("auth failure")
        data = bytearray()
        data.append(0)
        data.append(0)
        data.append(0)
        data.append(1)  # failure
        data.append(0)
        data.append(0)
        data.append(0)
        data.append(29)  # message length
        conn.send(data)
        conn.send(b"Invalid username or password.")
        return False


def handle_client(conn, addr):
    auth_success = False

    conn.send(VERSION)
    ver = conn.recv(len(VERSION)).decode()
    ver = str(ver).strip()
    print("client version: " + ver, addr)
    if ver == "RFB 003.008":
        conn.send(b"\x01\x1e")

        stype = conn.recv(1)

        print("security type chosen: ", stype)

        # if stype != b"\x02":
        #     print("unsupported security type {}".format(stype))
        #     conn.close()

    elif ver == "RFB 003.003":
        # 	/* Tell the client to use VNC auth */
        data = bytearray()
        data.append(0)
        data.append(0)
        data.append(0)
        data.append(2)
        conn.send(data)
        print("version 3.3")
    else:
        data = bytearray()
        data.append(0)  # /* 0 security types */
        data.append(0)
        data.append(0)
        data.append(0)
        data.append(20)  # /* 20-character message */
        conn.send(data)
        conn.send(b"Unsupported RFB version\n")
        conn.close()

    from binascii import unhexlify, hexlify
    import hashlib
    from Crypto.Cipher import AES
    # the following works
    from cryptography.hazmat.primitives.asymmetric import dh
    from cryptography.hazmat.backends import default_backend
    p = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff"
    server_public_key = "ac39363bc66c3de6c37862948e290ff5952009c588b3919dbed4b5da0aff759cc983e4a5881ea922f7ddeec666087a151bc105e4f327bf17e9990e26b380c503fef71bc1dbca485df441cd3adac51f1b04e3bdd7b2e1bd0ad8f7436c49124778b8d87114f188cfb73df5df29d3b7bf47fcec8e0da105c993412160faa9971f56"

    # generator: 2, key length: 128
    data = "00020080" + p + server_public_key
    databytes = unhexlify(data)
    conn.send(databytes)
    data = conn.recv(256)
    # data = hexlify(msg)
    encrypted_cred = data[:128]
    client_public_key = data[128:]
    client_public_key = int.from_bytes(client_public_key, 'big')

    p = int.from_bytes(unhexlify(p), 'big')
    g = 2
    pn = dh.DHParameterNumbers(p=p, g=g)
    parameters = pn.parameters(default_backend())
    client_public = dh.DHPublicNumbers(client_public_key, pn)
    client_public_key = client_public.public_key(default_backend())
    assert client_public_key.key_size == 1024
    shared_key = parameters.generate_private_key().exchange(client_public_key)
    print('shared key', shared_key)
    # get bytes of md5hash
    k = hashlib.md5(shared_key).digest()
    print(k)
    cipher = AES.new(k, AES.MODE_ECB)

    o = cipher.decrypt(encrypted_cred)
    o = ''.join('%02x' % c for c in o)
    print(o.decode("hex"))


def start_server():
    server_socket = None
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        server_socket.bind(("0.0.0.0", port))

        server_socket.listen(5)

        while True:
            try:
               conn, addr = server_socket.accept()
               print("Connection from: " + str(addr))
               start_new_thread(handle_client, (conn,addr))

            except:
                print(traceback.format_exc())
    except:
        print(traceback.format_exc())
        if server_socket:
            server_socket.close()
start_server()