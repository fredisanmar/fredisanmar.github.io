---
layout: post
title: tcpScanner.py
date: 2021-01-12 23:18 +0800
last_modified_at: 2021-01-12 23:18 +0800
tags: [tools, herramienta, python, code]
toc:  false
---

En este post voy a presentar la herramienta `tcpScanner.py`. 

La herramienta es un escaner de puertos que implementa multithreading.
```python
# coding=utf-8

import os
import socket
import argparse
import threading
from queue import Queue
import time


parser = argparse.ArgumentParser()
parser.add_argument("-i", '--IP', help='Dirección que IP',
                    metavar='', default='127.0.0.1')
parser.add_argument("-p", '--puertos', default=1-65535,
                    help='rango de puertos', metavar='', required=True, type=str)
parser.add_argument("-t", '--threads', type=int,
                    help='Numero de tareas', metavar='', default=10)
args = parser.parse_args()


print_lock = threading.Lock()  # thead lock para que workers funcionen mejor
queue = Queue()


print("████████╗ ██████╗██████╗       ███████╗ ██████╗ █████╗ ███╗   ██╗")
print("╚══██╔══╝██╔════╝██╔══██╗      ██╔════╝██╔════╝██╔══██╗████╗  ██║")
print("   ██║   ██║     ██████╔╝█████╗███████╗██║     ███████║██╔██╗ ██║")
print("   ██║   ██║     ██╔═══╝ ╚════╝╚════██║██║     ██╔══██║██║╚██╗██║")
print("   ██║   ╚██████╗██║           ███████║╚██████╗██║  ██║██║ ╚████║")
print("   ╚═╝    ╚═════╝╚═╝           ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝")
global var
var = args.puertos
global mode
mode = ''


if len(var.split("-")) == 2:
    minport, maxport = var.split("-")
    minport = int(minport)
    maxport = int(maxport)
    # print("-")
    mode = 1
elif len(var.split(",")) >= 2:
    puertos = var.split(",")
    puertos = list(map(int, puertos))
    mode = 2
elif len(var.split()) == 1:
    puertos = var
    mode = 3

def set_puertos(mode):
    if mode == 1: 
        for port in range(minport, maxport+1):
            queue.put(port)
        
    elif mode == 2:
        for port in puertos:
            queue.put(port)
        
    elif mode == 3:
        for port in {puertos}:
            queue.put(port)


def connections(port):
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with print_lock:
            #print(port)
            s.connect((args.IP, port))
            s.settimeout(0.1)
            s.close()
            return True 
    except:
        return False


def worker():

    while not queue.empty():
        port=queue.get()
        #print(port)
        if connections(port):
            print("Port "+"\033[35m {}\033[00m".format(port)+":  Open")
            

def main(mode):
    set_puertos(mode)

    thread_list=[]
    try:
        for thread in range(args.threads):
            thread=threading.Thread(target=worker)
            thread_list.append(thread)
            thread.start()
            time.sleep(1)
            thread.join()
            break
            exit
    except (KeyboardInterrupt, SystemExit):
        exit

main(mode)
```
## Uso de la herramienta.
Esta herramienta hace uso de la libreria argparse de python, por lo que la entrada de datos se parsea automaticamente.
Las opciones disponibles son:
* IP: La dirección IP se introduce con la opción -i o --IP. Por defecto la dirección IP está seteada a 127.0.0.1
* Puertos: Los puertos a escanear se setean con la opción -p o --puertos. Por defecto los puertos a escanear esán seteados para escanear todos los puertos.
* Threads: El número de threads o tareas se setean con la opción -t o --threads. Por defecto el numero de threads está seteado a 10.
