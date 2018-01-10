#!/usr/bin/python3
# -*- coding: utf-8 -*-

from random import randint
from time import gmtime, strftime, time
from uaclient import XML, log
from uaserver import EchoHandler
import hashlib
import socket
import socketserver
import sys


class USERS(socketserver.DatagramRequestHandler):
    """
    Users class
    """
    dic = {}
    dic_nonc = {}

    def user_create(self, base):
        """
        Escribe en un fichero
        """
        with open(base, 'w') as file:
            """
            for USER in self.dic:
                line = (USER + ', ' + self.dic[USER][0] + ', ' +
                       str(self.dic[USER][1]) + ', ' + str(self.dic[USER][2]) +
                       ', ' + str(self.dic[USER][4]) + '\r\n')
            file.write(line)
            """
            file.write(str(self.dic).replace('], ', '\r\n'))
            #file.write(' '.join(self.dic))

    def register(self):
        """
        Comprueba usuarios expirados
        """
        try:
            with open(base, 'r') as file:
                #file.readline(str(self.dic))
                self.expiration()
        except(FileNotFoundError):
            pass

    def expiration(self):
        """
        Borra elementos expirados
        """
        expired = []
        time_exp = strftime('%Y-%m-%d %H:%M:%S', gmtime(time()))
        for USER in self.dic:
            if self.dic[USER][3] <= time_exp:
                expired.append(USER)
        for USER in expired:
            del self.dic[USER]

    def keyfile(self, USER, psw_file):  #METEER path
        """
        Escribe en un fichero usuario y contraseña
        """
        with open(psw_file, "r") as fpas:
            PASW = None
            for line in fpas:
                USER_P = line.split(' ')[1]
                if USER == USER_P:
                    PASW = line.split()[3]
                    break
            return PASW

    def check(self, nonce, USER):
        """
        Pasa por hash para sacar numero
        """
        fcheck = hashlib.md5()
        fcheck.update(bytes(str(nonce), "utf-8"))
        fcheck.update(bytes(self.keyfile(USER, psw_file), "utf-8"))
        fcheck.digest()
        return fcheck.hexdigest()

    def sent_uaserver(self, IP_SERV, PORT_SERV, METHOD, line):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
            my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            try:
                my_socket.connect((IP_SERV, PORT_SERV))
                my_socket.send(bytes(line.decode('utf-8'), 'utf-8') + b'\r\n')
                recive = ""

                if METHOD != 'ACK':
                    recive = my_socket.recv(1024).decode('utf-8')
                    print("--ANSWER: \r\n" + recive)
                    recive = ('\r\n').join(recive.split('\r\n'))
                my_socket.close()
            except ConnectionRefusedError:
                NOPORT = ('20101018160243 Error: No server listening at ' +
                           IP_SERV + 'port ' + str(PORT_SERV))
                recive = 'SIP/2.0 504 Server Time-out\r\n\r\n'
            return recive

    def handle(self):
        """
        handle method of the server class
        """
        if self.dic == {}:
            self.register()
        self.expiration()
        line = self.rfile.read()
        WORD = line.decode('utf-8').split()
        METHOD = WORD[0]
        if line and line.decode('utf-8')[:8] == 'REGISTER':
            USER = WORD[1][4:-5]
            IP = self.client_address[0]
            PORT = WORD[1].split(':')[2]
            EXPIRE_NUM = WORD[4]
            EXPIRES = int(EXPIRE_NUM)+time()
            EXPIRE = strftime('%Y-%m-%d %H:%M:%S', gmtime(EXPIRES))
            if WORD[4] != '0':
                if USER in self.dic:
                    print('Ya registrado: ', EXPIRE_NUM)
                    self.dic[USER] = [IP, PORT, EXPIRES, EXPIRE, EXPIRE_NUM]
                    message = 'SIP/2.0 200 OK  \r\n\r\n'
                    self.wfile.write(bytes(message, 'utf-8'))
                    #log.logsent(IP, PORT, message)
                else:
                    if line.decode('utf-8').split('\r\n')[2]:
                        if WORD[5][0:-1] == 'Authorization':
                            NUM_CLIENT = WORD[7][10:-1]
                            NUM_PROXY = self.check(self.dic_nonc[USER], USER)
                            if NUM_CLIENT == NUM_PROXY:
                                self.dic[USER] = [IP, PORT, EXPIRES, EXPIRE, 
                                                    EXPIRE_NUM]
                                message = 'SIP/2.0 200 OK  \r\n\r\n'
                                self.wfile.write(bytes(message, 'utf-8'))
                                #log.logsent(IP, PORT, message)
                                self.user_create(base)
                            else:
                                message = 'SIP/2.0 400 Bad Request\r\n\r\n'
                                self.wfile.write(bytes(message, 'utf-8'))
                                #log.logsent(IP, PORT, message)
                    else:
                        nonce = randint(0, 99999999999999999)
                        self.dic_nonc[USER] = str(nonce)
                        message = ('SIP/2.0 401 Unauthorized\r\n' +
                                  'WWW Authenticate: Digest nonce="' +
                                   str(nonce))
                        self.wfile.write(bytes(message, 'utf-8') + b'" \r\n')
                        #log.logsent(IP, PORT, message)
            else:
                self.dic[USER] = [IP, PORT, EXPIRES, EXPIRE, EXPIRE_NUM]
                try:
                    del self.dic[USER]
                    self.user_create(base)
                    print(' USER DELETE')
                except(KeyError):
                    self.wfile.write(b' NOTICE: This user dont exist!')
        elif line and METHOD == 'INVITE' or METHOD == 'BYE' or METHOD == 'ACK':
            USER = WORD[1][4:]
            if USER in self.dic:
                #PORT_SERV = int('7002')
                IP_SERV = self.dic[USER][0]
                PORT_SERV = int(self.dic[USER][1])
                message = self.sent_uaserver(IP_SERV, PORT_SERV, METHOD, line)
                self.wfile.write(bytes(message, 'utf-8') + b'\r\n\r\n')
                #log.logrecive(IP, PORT, message)
            else:
                message = 'SIP/2.0 404 User Not Found\r\n\r\n'
                self.wfile.write(bytes(message, 'utf-8'))
                #log.logsent(IP, PORT, message)
            if METHOD == 'ACK':
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
                    print('AAACKKKK')
                    print(IP_SERV)
                    print('puerto: ', PORT_SERV)
                    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    my_socket.connect((IP_SERV, PORT_SERV))
                    my_socket.send(bytes(line.decode('utf-8'), 'utf-8') + b'\r\n')
        else:
            message = 'SIP/2.0 405 Method Not Allowed \r\n\r\n'
            self.wfile.write(bytes(message, 'utf-8'))
            #log.logsent(IP, PORT, message)
        log.logsent(IP, PORT, message)
        print(line.decode('utf-8'), end='')
        print(self.dic)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(' Usage: python proxy_registrar.py config')

    CONFIG = sys.argv[1]
    XML.parse()
    IP = XML.dic['server_ip']
    PORT = int(XML.dic['server_port'])
    base = XML.dic['database_path']
    psw_file = XML.dic['database_passwdpath']
    fichero = XML.dic['log_path']

    abro = open(base, 'w')
    abro.close()

    log = log(fichero)
    SERV = socketserver.UDPServer((IP, PORT), USERS)
    print('Server V listening at port ' + str(PORT) + '...')
    SERV.serve_forever()
