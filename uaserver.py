#!/usr/bin/python3
# -*- coding: utf-8 -*-
from random import randint
from uaclient import XML
from xml.sax import make_parser
import os
import socketserver
import sys

class EchoHandler(socketserver.DatagramRequestHandler):
    def error(self, line):
        """
        Busca errores en la petición
        """
        line_error = line.split(' ')
        line_one = line.split('\r\n')
        print(line_one[0])
        fail = False
        if line_one[0] and len(line_error) != 4: #ver deberia ser 3
            fail = True
        if line_error[1][0:4] != 'sip:':
            fail = True
        if 'SIP/2.0\r\n' not in line_error[2]:
            fail = True
        if '@' not in line_error[1]:
            fail = True
        return fail
    
    def handle(self):
        """
        Envia respuesetas según método
        """
        while 1:
            # Leyendo línea a línea lo que nos envía el cliente
            line = self.rfile.read()
            lista = ['INVITE', 'BYE', 'ACK', 'REGISTER']
            method = ((line.decode('utf-8')).split(' ')[0])
            if not line:
                break
            if method not in lista:
                self.wfile.write(b'SIP/2.0 405 Method Not Allowed \r\n\r\n')
            elif self.error(line.decode('utf-8')):
                self.wfile.write(b'SIP/2.0 400 Bad Request')
            elif method == lista[0]:
                self.wfile.write(b'SIP/2.0 100 Trying \r\n\r\n' +
                                 b'SIP/2.0 180 Ringing \r\n\r\n' +
                                 b'SIP/2.0 200 OK  \r\n\r\n')
            elif method == lista[1]:
                self.wfile.write(b'SIP/2.0 200 OK  \r\n')
            elif method == lista[2]:
                aEjecutar = "./mp32rtp -i " + IP + " -p " + str(PORT)
                aEjecutar += " < " + CANCION
                print("Enviamos RTP: ", aEjecutar)
                os.system(aEjecutar)
            elif method == lista[3]:
                self.wfile.write(b'SIP/2.0 200 OK  \r\n\r\n' +
                                 b'SIP/2.0 401 Unauthorized\r\n' +
                                 b'WWW Authenticate: Digest nonce="' + b'" \r\n')
                                 #b'randint(0,99999999999999999)' + b'" \r\n')
            print(' The client send:\r\n' + line.decode('utf-8'))
if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(' Usage: python3 uaserver.py config')

    CONFIG = sys.argv[1]
    XML.parse()

    IP = XML.dic['uaserver_ip']
    PORT = int(XML.dic['uaserver_port'])
    CANCION = XML.dic['audio_path']
    SERV = socketserver.UDPServer((IP, PORT), EchoHandler)
    print("Listening...")
    SERV.serve_forever()
