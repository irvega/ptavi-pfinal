#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Programa cliente que abre un socket a un servidor
"""

from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import socket
import sys

METODO = sys.argv[2]
LINE = sys.argv[3]
CONFIG = sys.argv[1] #ua1.xml
IP = '127.0.0.1'
PORT = int('6001')

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
    def log(self):
        """
        Escribe en un fichero json
        """
        open('log.xml', 'w'))

    def log1(self):
        """
        Comprueba si hay fichero log
        """
        try:
            with open('log.xml', 'r') as file:
                logg = load(file)
                self.expiration()
        except(FileNotFoundError):
            pass

 #def log():
if __name__ == "__main__":
    if len(sys.argv)!=4:
        sys.exit('Usage: python uaclient.py config method option')
    parser = make_parser()
    archivo=XML()
    parser.setContentHandler(archivo)
    parser.parse(open(CONFIG))
    print(archivo.dictio())

    IP = XML.dic['uaserver_ip']
    PORT = int(XML.dic['uaserver_port'])
    USER = XML.dic['account_username']

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
        my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        my_socket.connect((IP, PORT))

        print('Enviando:' + LINE)
        if METODO == 'REGISTER':
            my_socket.send(bytes('REGISTER sip:'+USER+' SIP/2.0\r\nExpires: ' +
                                 LINE+'\r\n\r\n', 'utf-8') + b'\r\n')
        if METODO == 'INVITE':
            my_socket.send(bytes('INVITE sip:'+LINE+' SIP/2.0\r\n', 'utf-8') +
                           b'\r\n')
        if METODO == 'BYE':
            my_socket.send(bytes('BYE sip:' + LINE + ' SIP/2.0\r\n', 'utf-8') +
                           b'\r\n')
    """
        DATA = my_socket.recv(1024)
        print('Recibido -- ', data.decode('utf-8'))
        RECIVE = data.decode('utf-8').split(' ')
        for element in RECIVE:
            if element == '200' and metodo != 'BYE':
                my_socket.send(bytes('ACK sip:' + LINE.split(':')[0] +
                                     ' SIP/2.0\r\n', 'utf-8') + b'\r\n')
    """   
