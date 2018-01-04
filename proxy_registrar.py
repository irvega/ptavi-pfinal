#!/usr/bin/python3
# -*- coding: utf-8 -*-

from random import randint
from time import gmtime, strftime, time
from uaclient import XML
from uaserver import EchoHandler
import socketserver
import sys


class USERS(socketserver.DatagramRequestHandler):
    """
    Users class
    """
    dic = {}

    def user_create(self):
        """
        Escribe en un fichero
        """
        with open('basedatos.txt', 'w') as file:
                file.write(str(self.dic))

    def register(self):
        """
        Comprueba usuarios expirados
        """
        try:
            with open('basedatos.txt', 'r') as file:
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
    """
    def keyfile(self,USER):
        ""
        Escribe en un fichero usuario y contraseña
        ""
        with open(open('passwords.txt', "r") as fpas:
            for line in fpas:
                USER_P = line.split(' ')[1]
                if USER == USER_P:
                    PASW = line.split(' ')[3]
                    break
            return PASW

    def check(nonce_user, user):
        ""
        Pasa por hash para sacar numero
        ""
        fcheck = hashlib.md5()
        fcheck.update(bytes(nonce_user, "utf-8"))
        fcheck.update(bytes(keyfile(USER)), "utf-8"))
        function_check.digest() 
        return function_check.hexdigest()
    """
    def handle(self):
        """
        handle method of the server class
        (all requests will be handled by this method)
        """
        if self.dic == {}:
            self.register()
        self.expiration()
        print(self.client_address)

        line = self.rfile.read()
        if line and line.decode('utf-8')[:8] == 'REGISTER':
            USER = line.decode('utf-8').split()[1][4:]
            IP = self.client_address[0]
            PORT = self.client_address[1]
            #with open('passwords.xml', 'r') as file:
            #    if USER not in file:
            #        self.wfile.write(b'SIP/2.0 400 Bad Request  \r\n\r\n')
        #elif line.decode('utf-8').split()[3][:7] == 'Expires':
            EXPIRE_NUM = line.decode('utf-8').split()[4]
            EXPIRES = int(EXPIRE_NUM)+time()
            EXPIRE = strftime('%Y-%m-%d %H:%M:%S', gmtime(EXPIRES))
            if line.decode('utf-8').split()[4] != '0':
                self.dic[USER] = [IP, PORT, EXPIRES, EXPIRE, EXPIRE_NUM]
                #self.CAD = USER + ':' + IP + str(PORT) + str(EXPIRES) + EXPIRE +'\r\n'
                self.user_create()
                #if USER not in self.dic:
                nonce = randint(0, 99999999999999999)
                if line.decode('utf-8').split('\r\n')[2]:
                    if line.decode('utf-8').split()[5][0:-1] == 'Authorization':
                        NUM_CLIENT = line.decode('utf-8').split()[7][10:-1]
                        NUM_PROXY = nonce
                        #NUM_PROXY = checking(self.nonces[USER], USER)
                        if NUM_CLIENT == 'NUM_PROXY':
                            print('SIIIIII')
                            self.wfile.write(b'SIP/2.0 200 OK  \r\n\r\n')
                        else:
                            print('NOOO')
                            self.wfile.write(b'SIP/2.0 400 Bad Request\r\n\r\n')
                else:
                    self.wfile.write(b'SIP/2.0 401 Unauthorized\r\n' +
			                         b'WWW Authenticate: Digest nonce="' +
                                     bytes(str(nonce), 'utf-8') + b'" \r\n')
            else:
                try:
                    del self.dic[USER]
                    self.user_create()
                    self.wfile.write(b'SIP/2.0 200 OK  \r\n\r\n')
                    self.wfile.write(b' USER DELETE')
                except(KeyError):
                    self.wfile.write(b' NOTICE: This user dont exist!')
        print(line.decode('utf-8'), end='')
        print(self.dic)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(' Usage: python proxy_registrar.py config')

    CONFIG = sys.argv[1]
    XML.parse()
    IP = XML.dic['server_ip']
    PORT = int(XML.dic['server_port'])
    SERV = socketserver.UDPServer((IP, PORT), USERS)
    print('Server V listening at port ' + str(PORT) + '...')
    SERV.serve_forever()
