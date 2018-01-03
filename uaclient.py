#!/usr/bin/python3
# -*- coding: utf-8 -*-

from random import randint
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import socket
import sys

class XML(ContentHandler):
    dic = {}
    def __init__(self):
        """
        Crea un diccionario
        """
        self.label = {'account': ['username', 'password'],
                      'uaserver':  ['ip', 'port'],
                      'rtpaudio': ['port'],
                      'regproxy': ['ip', 'port'],
                      'log': ['path'],
                      'audio': ['path']
                      }
    def startElement(self, name, attrs):
        """
        Guarda de name_atri
        """
        if name in self.label:
            for atrib in self.label[name]:
                self.dic[name + "_" + atrib] = attrs.get(atrib, "")
    def dictio(self):
        """
        Devuelve el diccionario
        """
        return(self.dic)
    def parse():
        """
        Lee el fichero
        """
        CONFIG = sys.argv[1] #ua1.xml
        parser = make_parser()
        archivo=XML()
        parser.setContentHandler(archivo)
        parser.parse(open(CONFIG))
        confdict = archivo.dictio()
        
if __name__ == "__main__":
    if len(sys.argv)!=4:
        sys.exit('Usage: python uaclient.py config method option')
    METODO = sys.argv[2]
    LINE = sys.argv[3]

    def log(logfile, tipo, ip, message):
        """
        Escribe en un fichero
        """
        df = open('logfile', 'a')

    XML.parse()
    IP = XML.dic['uaserver_ip']
    PORT = int(XML.dic['uaserver_port'])   
    USER = XML.dic['account_username']
    PORT_AUDIO = XML.dic['rtpaudio_port']

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
        my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        my_socket.connect((IP, PORT))

        if METODO == 'REGISTER':
            message = 'REGISTER sip:'+USER+' SIP/2.0\r\nExpires: '+LINE+'\r\n'
            my_socket.send(bytes(message + '\r\n', 'utf-8') + b'\r\n')
            #log(confdict['logfile'], 'sent', IP, message,'\r\n')
        elif METODO == 'INVITE':
            message = ('INVITE sip:'+USER+' SIP/2.0\r\n' + 'Content-Type: ' +
                       'application/sdp\r\n\r\n' + 'v=0\r\no=' + USER + ' ' + 
                       str(PORT) + '\r\ns=misesion\r\nt=0\r\nm=audio ' +
                       PORT_AUDIO + ' RTP\r\n\r\n')
            my_socket.send(bytes(message, 'utf-8')+b'\r\n\r\n')
        elif METODO == 'BYE':
            my_socket.send(bytes('BYE sip:' + LINE + ' SIP/2.0\r\n', 'utf-8') +
                           b'\r\n')
        else:
            my_socket.send(bytes(METODO + ' sip: ' + LINE +
                                 ' SIP/2.0\r\n', 'utf-8') + b'\r\n\r\n')

        DATA = my_socket.recv(1024)
        print('Recibido:', DATA.decode('utf-8'))
        RECIVE = DATA.decode('utf-8').split(' ')
        for element in RECIVE:
            if element == '401':
                my_socket.send(bytes(message + 
                               'Authorization: Digest response="' + 
                               str(randint(0,99999999999999999)) +
                               '"\r\n', 'utf-8') + b'\r\n')
            if element == '200' and METODO == 'INVITE':
                my_socket.send(bytes('ACK sip:' + USER +
                                     ' SIP/2.0\r\n', 'utf-8') + b'\r\n')

