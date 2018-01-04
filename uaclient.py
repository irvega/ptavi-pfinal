#!/usr/bin/python3
# -*- coding: utf-8 -*-

from random import randint
from time import gmtime, strftime, time
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
                      'audio': ['path'],
                      'server':['name', 'ip', 'port']
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
        archivo = XML()
        parser.setContentHandler(archivo)
        parser.parse(open(CONFIG))
        confdict = archivo.dictio()

if __name__ == "__main__":

    if len(sys.argv) != 4:
        sys.exit('Usage: python uaclient.py config method option')

    XML.parse()
    IP = XML.dic['uaserver_ip']
    PORT = int(XML.dic['uaserver_port'])
    PORT_RTP = int(XML.dic['rtpaudio_port'])
    USER = XML.dic['account_username']
    PORT_AUDIO = XML.dic['rtpaudio_port']
    archivo = XML()
    confdict = archivo.dictio()

    METODO = sys.argv[2]
    LINE = sys.argv[3]
    #SENT = IP + ':' + PORT + ': '
    def timenow():
        """
        Tiempo actual
        """
        timereal = strftime("%Y%m%d%H%M%S", gmtime(time()))
        return timereal
    #def log(logfile, tipo, ip, message):

        #try:
    logfile = open('logfile.txt', "a")
    logfile.write(str(timenow()) + " Starting...\n")
        #except FileNotFoundError:
        #    logfile = open('logfile', "w")

    def logsent(logfile):
        """
        Escribe en el log lo que envio
        """
        logfile.write(str(timenow()) + " Sent to " + IP + ':' + str(PORT) + ': ' +
                      message + "\n")

    def logrecive(logfile):
        """
        Escribe en el log lo que recivo
        """
        logfile.write(str(timenow()) + " Recived from " + IP + ':' + str(PORT) +
                      ': ' + str(''.join(RECIVE[1:-2]) + "\n"))

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
        my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        my_socket.connect((IP, PORT))

        if METODO == 'REGISTER':
            message = 'REGISTER sip:'+USER+' SIP/2.0\r\nExpires: '+LINE+'\r\n'
            my_socket.send(bytes(message + '\r\n', 'utf-8') + b'\r\n')
        elif METODO == 'INVITE':
            message = ('INVITE sip:'+USER+ ' SIP/2.0\r\n' + 'Content-Type: ' +
                       'application/sdp\r\n\r\n' + 'v=0\r\no=' + USER + ' ' +
                       str(PORT_RTP) + '\r\ns=vengadores\r\nt=0\r\nm=audio ' +
                       PORT_AUDIO + ' RTP\r\n\r\n')
            my_socket.send(bytes(message, 'utf-8')+b'\r\n\r\n')
        elif METODO == 'BYE':
            message =  ('BYE sip:' + LINE + ' SIP/2.0\r\n')
            my_socket.send(bytes(message, 'utf-8') + b'\r\n')
        else:
            my_socket.send(bytes(METODO + ' sip: ' + LINE +
                                 ' SIP/2.0\r\n', 'utf-8') + b'\r\n\r\n')
        try:
            DATA = my_socket.recv(1024)
        except ConnectionRefusedError:
            NOPORT = ('20101018160243 Error: No server listening at '+ IP +
                     ' port ' + str(PORT))
            logfile.write(NOPORT)
            sys.exit(NOPORT)
        logsent(logfile)

        print('Recibido:', DATA.decode('utf-8'))
        RECIVE = DATA.decode('utf-8').split(' ')
        logrecive(logfile)

        for element in RECIVE:
            if element == '401':
                my_socket.send(bytes(message +
                               'Authorization: Digest response="' +
                               str(randint(0, 99999999999999999)) +
                               '"\r\n', 'utf-8') + b'\r\n')
            if element == '200' and METODO == 'INVITE':
                my_socket.send(bytes('ACK sip:' + USER +
                                     ' SIP/2.0\r\n', 'utf-8') + b'\r\n')
            if element == '200' and METODO == 'BYE':
                logfile.write(str(timenow()) + " Finishing.\n")
                logfile.close()
