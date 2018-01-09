#!/usr/bin/python3
# -*- coding: utf-8 -*-

from random import randint
from time import gmtime, strftime, time
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import hashlib
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
                      'server':['name', 'ip', 'port'],
                      'account':['username','password']
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

class log():

    def __init__(self, fichero):
           #try:
        self.logfile = open(fichero, "a")
        self.logfile.write(str(timenow()) + " Starting...\n")  #CORREGIR
        #except FileNotFoundError:
        #    logfile = open('logfile', "w")

    def logsent(self, IP, PORT, message):
        """
        Escribe en el log lo que envio
        """
        self.logfile.write(str(timenow()) + " Sent to " + IP + ':' + str(PORT) +
                          ': ' + message.replace('\r\n','') + "\n")

    def logrecive(self, IP, PORT, message):
        """
        Escribe en el log lo que recivo
        """
        self.logfile.write(str(timenow()) + " Recived from " + IP + ':' + str(PORT) +
                      ': ' + str(' '.join(RECIVE[1:-1]) + "\n"))


if __name__ == "__main__":

    if len(sys.argv) != 4:
        sys.exit('Usage: python uaclient.py config method option')

    XML.parse()
    IP = XML.dic['uaserver_ip']
    IP_PX = XML.dic['regproxy_ip']
    PORT_PX = int(XML.dic['regproxy_port'])
    PORT = int(XML.dic['uaserver_port'])
    PORT_RTP = int(XML.dic['rtpaudio_port'])
    USER = XML.dic['account_username']
    USER_SERV = sys.argv[3]
    PORT_AUDIO = XML.dic['rtpaudio_port']
    PSW = XML.dic['account_password']
    fichero = XML.dic['log_path']
    archivo = XML()
    confdict = archivo.dictio()

    METODO = sys.argv[2]
    LINE = sys.argv[3]

    def timenow():
        """
        Tiempo actual
        """
        timereal = strftime("%Y%m%d%H%M%S", gmtime(time()))
        return timereal

    log = log(fichero)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
        my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        my_socket.connect((IP_PX, PORT_PX))

        if METODO == 'REGISTER':
            message = ('REGISTER sip:' + USER + ':' + str(PORT) +
                       ' SIP/2.0\r\nExpires: ' + LINE + '\r\n')
            my_socket.send(bytes(message + '\r\n', 'utf-8') + b'\r\n')
        elif METODO == 'INVITE':
            message = ('INVITE sip:'+ USER_SERV + ' SIP/2.0\r\n' +
                       'Content-Type: ' + 'application/sdp\r\n\r\n' +
                       'v=0\r\no=' + USER + ' ' + str(PORT_RTP) + '\r\ns=ven' +
                       'gadores\r\nt=0\r\nm=audio '+PORT_AUDIO + ' RTP\r\n\r\n')
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
                     ' port ' + str(PORT_PX))
            logfile.write(NOPORT)
            sys.exit(NOPORT)

        try:           
            log.logsent(IP, PORT, message)
        except NameError:
            pass
        print('Recibido:', DATA.decode('utf-8'))
        RECIVE = DATA.decode('utf-8').split(' ')
        log.logrecive(IP, PORT, message)

        def check(nonce):
            """
            Pasa por hash para sacar numero
            """
            fcheck = hashlib.md5()
            fcheck.update(bytes(nonce, "utf-8"))
            fcheck.update(bytes(PSW, "utf-8"))
            fcheck.digest() 
            return fcheck.hexdigest()

        for element in RECIVE:
            if element == '401':
                nonce = RECIVE[5][7:-1]
                new_nonce = check(nonce)
                message = (message + 'Authorization: Digest response="' +
                           new_nonce + '"\r\n')
                my_socket.send(bytes(message, 'utf-8') + b'\r\n')
                log.logsent(IP, PORT, message)
                DATA = my_socket.recv(1024)
                print('Recibido:', DATA.decode('utf-8'))
            if element == '200' and METODO == 'INVITE':
                message = ('ACK sip:' + USER + ' SIP/2.0\r\n'+'Content-Type: ' +
                           'application/sdp\r\n\r\n' + 'v=0\r\no=' + USER +
                           ' ' + str(PORT_RTP) + '\r\ns=vengadores\r\nt=0\r\n' +
                           'm=audio ' + PORT_AUDIO + ' RTP\r\n\r\n' + '\r\n')
                my_socket.send(bytes(message, 'utf-8') + b'\r\n')
                log.logsent(IP, PORT, message)
                DATA = my_socket.recv(1024)
                print('Recibido:', DATA.decode('utf-8'))
            if element == '200' and METODO == 'BYE':
                logfile = log()
                logfile.write(str(timenow()) + " Finishing.\n")
                log.logsent(IP, PORT, message)
                log.logfile.close()


