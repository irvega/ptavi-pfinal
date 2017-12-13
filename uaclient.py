#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Programa cliente que abre un socket a un servidor
"""

from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import socket
import sys

if len(sys.argv)!=4:
    sys.exit('Usage: python uaclient.py config method option')
METODO = sys.argv[2]
LINE = sys.argv[3]
CONFIG = sys.argv[1] #ua1.xml
IP = '127.0.0.1'
PORT = int('6001')
def log(logfile, tipo, ip, message):
    """
    Escribe en un fichero
    """
    df = open('logfile', 'a')

class XML(ContentHandler):
    dic = {}
    def __init__(self):
        self.label = {'account': ['username', 'password'],
                      'uaserver':  ['ip', 'port'],
                      'rtpaudio': ['port'],
                      'regproxy': ['ip', 'port'],
                      'log': ['path'],
                      'audio': ['path']
                      }
    def startElement(self, name, attrs):
        if name in self.label:
            for atrib in self.label[name]:
                self.dic[name + "_" + atrib] = attrs.get(atrib, "")
    def dictio(self):
        return(self.dic)

if __name__ == "__main__":

    parser = make_parser()
    archivo=XML()
    parser.setContentHandler(archivo)
    parser.parse(open(CONFIG))
    confdict = archivo.dictio()

    IP = XML.dic['uaserver_ip']
    PORT = int(XML.dic['uaserver_port'])
    USER = XML.dic['account_username']

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
        my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        my_socket.connect((IP, PORT))

        print('Enviando:' + LINE)
        if METODO == 'REGISTER':
            message = 'REGISTER sip:'+USER+' SIP/2.0\r\nExpires: '+LINE+'\r\n\r\n'
            my_socket.send(bytes(message, 'utf-8') + b'\r\n')
            #log(confdict['logfile'], 'sent', IP, message,'\r\n')
        if METODO == 'INVITE':
            message = 'INVITE sip:'+USER+' SIP/2.0\r\n', 'utf-8' +                           
                       b'\r\n'+ 'Content-Type: application/sdp'
            my_socket.send(bytes(message, 'utf-8')+b'\r\n\r\n')
        print(message)
        if METODO == 'BYE':
            my_socket.send(bytes('BYE sip:' + LINE + ' SIP/2.0\r\n', 'utf-8') +
                           b'\r\n')
    """
        DATA = my_socket.recv(1024)
        print('Recibido -- ', data.decode('utf-8'))
        RECIVE = data.decode('utf-8').split(' ')
        for element in RECIVE:
            if element == '401':
                my_socket.send(bytes(message, 'utf-8') + 'Authorization: Digest              
                               response="numero aleatorio"' +
                               ' SIP/2.0\r\n', 'utf-8') + b'\r\n')
    """   
