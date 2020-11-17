#!/usr/bin/env pyton
# -*- coding: utf-8 -*-

from __future__ import division, print_function

import os
import sys
import time 
import array
import socket
import struct
import select
import signal
import ctypes
import logging

if __name__ == '__main__':
    import argparse
    
STD_INPUT_HANDLE   = -10
STD_OUTPUT_HANDLE  = -11
STD_ERROR_HANDLE   = -12

'''
std_out_handle = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
 
def set_color(color, handle=std_out_handle):
    bool = ctypes.windll.kernel32.SetConsoleTextAttribute(handle, color)
'''

ICMP_ECHOREPLY = 0
ICMP_ECHO = 8

def signal_handler(sig, frame):
    logger.info("Ping stopped by user (Ctrl + C) ")
    sys.exit(0)

def _checksum(source_string):
    """
    A port of the functionality of in_cksum() from ping.c
    Ideally this would act on the string as a series of 16-bit ints (host
    packed), but this works.
    Network data is big-endian, hosts are typically little-endian
    """
    if (len(source_string) % 2):
        source_string += "\x00"
    converted = array.array("H", source_string)
    if sys.byteorder == "big":
        converted.bytewap()
    val = sum(converted)

    val &= 0xffffffff  # Truncate val to 32 bits (a variance from ping.c, which
    # uses signed ints, but overflow is unlikely in ping)

    val = (val >> 16) + (val & 0xffff)  # Add high 16 bits to low 16 bits
    val += (val >> 16)  # Add carry from above (if any)
    answer = ~val & 0xffff  # Invert and truncate to 16 bits
    answer = socket.htons(answer)

    return answer

def mping(list):
    myChecksum  = 0
    myID        = 0
    mySeqNumber = 0
    startVal    = 0x42
    padBytes    = []
    dataSize    = 32
    ICMP_MAX_BUF    = 512

    pingResult = {}
    for i in list :
        pingResult[i] = [0, 0]

    # Make ICMP ECHO Request Packet
    for i in range(startVal, startVal + (dataSize - 8)) :
        padBytes + [ (i & 0xff) ]
    data = bytearray(padBytes)

    # Make dummy header for checksum
    header = struct.pack(
        "!BBHHH", ICMP_ECHO, 0, myChecksum, myID, mySeqNumber
    )

    myChecksum = _checksum(header + data)

    header = struct.pack(
            "!BBHHH", ICMP_ECHO, 0, myChecksum, myID, mySeqNumber
    )
    
    packet = header + data

    try:
        mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                    socket.getprotobyname("icmp"))
        mySocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    except OSError as e:
        logger.error("Socket Fail : %s"%str(e))
    

    sentTime = time.perf_counter()

    for i in iplist : 
        pingResult[i] = [sentTime, 0]

    try:
        for addr in iplist :
            mySocket.sendto(packet, (addr, 1))
    except OSError as e:
        logger.error("General Error : Sending Fail (%s) "%str(e))
        return
    except socket.error as e:
        logger.error("Socket Error : Sending Fail (%s) "%str(e))
        return


    timeout = 2
    while True:
        readyList = select.select([mySocket], [], [], timeout)

        if readyList[0] == []:  # TimeOut
            break

        timeReceived = time.perf_counter()

        recvPacket, addr = mySocket.recvfrom(ICMP_MAX_BUF)

        ipHeader = recvPacket[:20]

        iphVersion, iphTypeOfSvc, iphLength, iphID, iphFlags, iphTTL, \
            iphProtocol, iphChecksum, iphSrcIP, iphDestIP = struct.unpack(
                "!BBHHHBBHII", ipHeader)

        icmpHeader = recvPacket[20:28]

        icmpType, icmpCode, icmpChecksum, icmpPacketID, icmpSeqNumber \
            = struct.unpack("!BBHHH", icmpHeader)     

        host_addr = socket.inet_ntop(socket.AF_INET, struct.pack(
                    "!I", iphSrcIP))

        if icmpCode == 0 :
            try :
                pingResult[host_addr][1] = timeReceived
            except KeyError :
                logger.error("Not in IP List - {:15s}".format(host_addr))

    total = 0
    dead = 0
    alive = 0
    loglist=time.strftime('%c',time.localtime(time.time()))

    '''
    for k, v in pingResult.items() :
        total = total + 1
        if total % 2 ==0 :
            eol = '\n'
        else :
            eol = '    '
        if v[1] != 0 :
            print("[{:4d}] {:15s} : {:6.0f}".format(total, k, (v[1]-v[0])*1000), end = eol, flush = True)
            alive = alive + 1
        else :
            set_color(0x47)
            print("[{:4d}] {:15s} : ......".format(total, k), end = eol, flush = True)
             
            # loglist = loglist + ','+ str(total) 
            set_color(0x07)
            dead = dead + 1

    set_color(0x57)
    print("\nTotal {} host, {} Alive, {} Dead : {}".format(len(iplist) , alive, dead, 
            time.strftime('%m-%d %H:%M:%S',time.localtime(time.time()))),flush=True)
    set_color(0x07)
    # logfile.write(loglist + '\n')
    print(" ", flush = True)
    '''
    for k, v in pingResult.items() :
        total = total +1
        if v[1] != 0 :
            logger.info("{:15s} : {:6.0f}".format(k, (v[1]-v[0])*1000))
            alive = alive + 1
        else :
            logger.info("{:15s} : ......".format(k, (v[1]-v[0])*1000))
            dead = dead + 1

    logger.info(" *** Ping Result : Total {} host, {} Alive, {} Dead ".format(len(pingResult) , alive, dead))



if __name__ == "__main__" :
    parser = argparse.ArgumentParser(description="This")
    parser.add_argument('-f', nargs=1)
    parser.add_argument('-r', nargs=3)
    parser.add_argument('-v')
    opt = parser.parse_args()

    logger = logging.getLogger("pingLogger")
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(levelname)5s - %(message)s')

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    filename = time.strftime("%Y%m%d_%H_%M_Ping.log")

    file_handler = logging.FileHandler(filename)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    signal.signal(signal.SIGINT, signal_handler)

    if opt.f :
        file = open(opt.f[0])
        iplist = file.read().splitlines()
    elif opt.r :
        iplist = []
        for i in range(int(opt.r[1]), int(opt.r[2])+1):
            iplist.append(opt.r[0]+'.'+str(i))
    elif opt.v :
        logger.setLevel(logging.DEBUG)
    else :
        msg = """\nUsage : 
            python myping.py -f ping_ip_list.txt
            python myping.py -r 172.31.1 10 20
            -> ping to 172.31.1.10 ~ 172.31.1.20
        """
        logger.error(msg)
        exit()


    # filename = time.strftime("%Y%m%d_%H_%M_Ping.log")
    # logfile = open(filename,'a+')

    logger.info("Ping Start")
    while True:
        mping(iplist)   
    logger.info("Ping End!!") 
