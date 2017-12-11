#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Programa cliente que abre un socket a un servidor
"""

from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import socket
import sys

#METODO = sys.argv[1]

class XML(ContentHandler):
    def __init__(self):
        self.dic = {}
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
            IP = self.dic['uaserver_ip']
            PORT = self.dic['uaserver_port']
    def dictio(self):
        return(self.dic)

    #def log():
if __name__ == "__main__":
    parser = make_parser()
    archivo=XML()
    parser.setContentHandler(archivo)
    parser.parse(open('ua2.xml'))
    print(archivo.dictio())
