#!/usr/bin/python3
# -*- coding: utf-8 -*-
from random import randint
from uaclient import XML, log
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
        line_one = ''.join(line.split('\r\n')[0]).split()
        fail = False
        if len(line_one) != 3:
            fail = True
            print(fail)
        if line_error[1][0:4] != 'sip:' or 'SIP/2.0\r\n' not in line_error[2]:
            fail = True
        if '@' not in line_error[1]:
            fail = True
        return fail

    def handle(self):
        """
        Envia respuestas según método
        """
        while 1:
            line = self.rfile.read()
            lista = ['INVITE', 'BYE', 'ACK']
            method = ((line.decode('utf-8')).split(' ')[0])
            if not line:
                break
            if method not in lista:
                message = 'SIP/2.0 405 Method Not Allowed\r\n\r\n'
                self.wfile.write(bytes(message, 'utf-8'))
                log.logsent(IP, PORT, message)
            elif self.error(line.decode('utf-8')):
                message = 'SIP/2.0 400 Bad Request\r\n\r\n'
                self.wfile.write(bytes(message, 'utf-8'))
                log.logsent(IP, PORT, message)
            elif method == lista[0]:
                message = ('SIP/2.0 100 Trying \r\n\r\n' + 
                           'SIP/2.0 180 Ringing \r\n\r\n' +
                           'SIP/2.0 200 OK  \r\n\r\n' + 
                           'Content-Type: application/sdp\r\n\r\n' +
                           'v=0\r\no=' + USER + ' ' + IP + '\r\ns=ven' +
                           'gadores\r\nt=0\r\nm=audio '+
                            str(PORT_RTP) + ' RTP\r\n\r\n')
                self.wfile.write(bytes(message, 'utf-8'))
                log.logsent(IP, PORT, message) 
                #FALTA SDP 
                PORT_CL = (line.decode('utf-8').split(' ')[5])
                IP_CL = (line.decode('utf-8').split(' ')[4].split('\r\n')[0])
            elif method == lista[1]:
                message = 'SIP/2.0 200 OK  \r\n\r\n'
                self.wfile.write(bytes(message, 'utf-8'))
                log.logsent(IP, PORT, message) 
                log.cierre()
            elif method == lista[2]:
                aEjecutar = "./mp32rtp -i " + IP_CL + " -p " + str(PORT_CL)
                aEjecutar += " < " + CANCION
                print("Enviamos RTP: ", aEjecutar)
                os.system(aEjecutar)
            print(' The client send:\r\n' + line.decode('utf-8'))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(' Usage: python3 uaserver.py config')

    XML.parse()
    IP = XML.dic['uaserver_ip']
    PORT = int(XML.dic['uaserver_port'])
    CANCION = XML.dic['audio_path']
    USER = XML.dic['account_username']
    PORT_RTP = int(XML.dic['rtpaudio_port'])
    fichero = XML.dic['log_path']

    def timenow():
        """
        Tiempo actual
        """
        timereal = strftime("%Y%m%d%H%M%S", gmtime(time()))
        return timereal

    log = log(fichero)
    SERV = socketserver.UDPServer((IP, PORT), EchoHandler)
    print("Listening...")
    SERV.serve_forever()
