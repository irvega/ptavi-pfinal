#!/usr/bin/python3
# -*- coding: utf-8 -*-
from random import randint
from uaclient import XML, log
from xml.sax import make_parser
import os
import socket
import socketserver
import sys


class EchoHandler(socketserver.DatagramRequestHandler):

    dic = {}

    def handle(self):
        """
        Envia respuestas según método
        """
        while 1:
            IP = IP_PX
            PORT = PORT_PX
            line = self.rfile.read()
            RECIVE = line.decode('utf-8').split(' ')
            log.logrecive(IP, PORT, RECIVE, fichero)
            lista = ['INVITE', 'BYE', 'ACK']
            method = ((line.decode('utf-8')).split(' ')[0])
            if not line:
                break
            if method not in lista:
                message = 'SIP/2.0 405 Method Not Allowed\r\n\r\n'
                self.wfile.write(bytes(message, 'utf-8'))
            elif method == lista[0]:
                message = ('SIP/2.0 100 Trying \r\n\r\n' +
                           'SIP/2.0 180 Ringing \r\n\r\n' +
                           'SIP/2.0 200 OK \r\n\r\n' +
                           'Content-Type: application/sdp\r\n\r\n' +
                           'v=0\r\no=' + USER + ' ' + IP + '\r\ns=ven' +
                           'gadores\r\nt=0\r\nm=audio ' + str(PORT_RTP) +
                           ' RTP\r\n\r\n')
                self.wfile.write(bytes(message, 'utf-8'))
                USER_CL = (line.decode('utf-8').split(' ')[3].split('=')[2])
                PORT_CL = (line.decode('utf-8').split(' ')[5])
                IP_CL = (line.decode('utf-8').split(' ')[4].split('\r\n')[0])
                self.dic[IP_CL] = PORT_CL
            elif method == lista[1]:
                message = 'SIP/2.0 200 OK  \r\n\r\n'
                self.wfile.write(bytes(message, 'utf-8'))
                log.logsent(IP, PORT, message, fichero)
                log.cierre(fichero)
            elif method == lista[2]:
                IP_CL = self.client_address[0]
                if IP_CL in self.dic:
                    aEjecutar = ("./mp32rtp -i " + IP_CL + " -p " +
                                 str(self.dic[IP_CL]))
                    aEjecutar += " < " + CANCION
                    print("Enviamos RTP: ", aEjecutar)
                    os.system(aEjecutar)
                try:
                    del self.dic[IP_CL]
                except KeyError:
                    pass
            print(' The client send:\r\n' + line.decode('utf-8'))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(' Usage: python3 uaserver.py config')

    XML.parse()
    IP = XML.dic['uaserver_ip']
    PORT = int(XML.dic['uaserver_port'])
    IP_PX = XML.dic['regproxy_ip']
    PORT_PX = int(XML.dic['regproxy_port'])
    CANCION = XML.dic['audio_path']
    USER = XML.dic['account_username']
    PORT_RTP = int(XML.dic['rtpaudio_port'])
    fichero = XML.dic['log_path']

    log = log(fichero)
    SERV = socketserver.UDPServer((IP, PORT), EchoHandler)
    print("Listening...")
    SERV.serve_forever()
