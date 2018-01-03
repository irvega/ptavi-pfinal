#!/usr/bin/python3
# -*- coding: utf-8 -*-

from time import gmtime, strftime, time
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
        with open('passwords.txt', 'w') as file:
                file.write(str(self.dic))
    """
    def register(self):
        
        Comprueba usuarios expirados
        
        try:
            with open('passwords.txt', 'r') as file:
                file.readline(str(self.dic))
                #self.expiration()
        except(FileNotFoundError):
            pass
    
    def expiration(self):

        Borra elementos expirados

        expired = []
        time_exp = strftime('%Y-%m-%d %H:%M:%S', gmtime(time()))
        for user in self.dic:
            if self.dic[user][1] <= time_exp:
                expired.append(user)
        for user in expired:
            del self.dic[user]
    """
    def handle(self):
        """
        handle method of the server class
        (all requests will be handled by this method)
        """
        if self.dic == {}:
            #self.register()

        #self.expiration()
            print(self.client_address)
        for line in self.rfile:
            if not line:
                break
            if line and line.decode('utf-8')[:8] == 'REGISTER':
                self.wfile.write(b'SIP/2.0 200 OK  \r\n\r\n')
                USER = line.decode('utf-8')[13:-10]
                IP = self.client_address[0]
                PORT = self.client_address[1]
            elif line and line.decode('utf-8')[:7] == 'Expires':
                EXPIRES = int(line.decode('utf-8')[9:])+time()
                EXPIRE = strftime('%Y-%m-%d %H:%M:%S', gmtime(EXPIRES))
                if line.decode('utf-8').split()[1] != '0':
                    self.wfile.write(b'SIP/2.0 401 Unauthorized\r\n' +
                                     b'WWW Authenticate: Digest nonce="' +
                                     b'" \r\n\r\n')
                    #b'randint(0,99999999999999999)' + b'" \r\n')
                    self.dic[USER] = [IP, PORT, EXPIRES, EXPIRE]
                    self.user_create()
                else:
                    try:
                        del self.dic[USER]
                        self.user_create()
                    except(KeyError):
                        print('  NOTICE: This user dont exist!')
            print(line.decode('utf-8'), end='')
        print(self.dic)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(' Usage: python proxy_registrar.py config')

    IP = '127.0.0.1'
    PORT = 6005
    SERV = socketserver.UDPServer((IP, PORT), USERS)
    print('Server V listening at port 6005...')
    SERV.serve_forever()
