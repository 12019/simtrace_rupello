import os
import sys
import struct
from string import ascii_letters, digits, punctuation

simtrace_hdr_fmt = '<bbbb'
simtrace_hdr_len = struct.calcsize(simtrace_hdr_fmt)

SIMTRACE_MSGT_NULL = 0
SIMTRACE_MSGT_DATA = 1
SIMTRACE_MSGT_RESET = 2

SIMTRACE_FLAG_ATR        = 0x01
SIMTRACE_FLAG_WTIME_EXP  = 0x04
SIMTRACE_FLAG_PPS_FIDI   = 0x08

def printable(value):
    char = chr(value)
    if char in ascii_letters or \
       char in digits or \
       char in punctuation or \
       char == ' ':
        return char
    else:
        return '.'    

def bufferToHex(buffer):
    return ' '.join(['%02X' % ord(b) for b in buffer]) 

def bufferToAscii(buffer):
    return ''.join([printable(ord(b)) for b in buffer]) 

def printhex(data,bytesperline=20):
    for i in range(len(data)/bytesperline):
        fr = i*bytesperline
        to = fr + bytesperline
        print '%s | %s' % ( bufferToHex(data[fr:to]),
                            bufferToAscii(data[fr:to]))
    remaining = len(data) % bytesperline
    if remaining>0:
        print '%s | %s' % ( bufferToHex(data[-remaining:]).ljust((bytesperline*3)-1),
                            bufferToAscii(data[-remaining:]))     

def print_packet(cmd,flags,res0,res1,hdr_buf,apdu_buf):
    if cmd == SIMTRACE_MSGT_DATA:
        print '--header--'
        print bufferToHex(hdr_buf)
        print '--APDU Data--'
        printhex(apdu_buf,bytesperline=16)
        if (flags & SIMTRACE_FLAG_ATR) > 0:
            print 'ATR'
            print 'call apdu_out_cb'
        else:
            if (flags & SIMTRACE_FLAG_PPS_FIDI) > 0:
                print 'PPS (Fi=%u/Di=%u)' % (res0,res1)
            print 'call apdu_split_in'  
            if (flags & SIMTRACE_FLAG_WTIME_EXP) > 0:
                print 'call apdu_split_boundary'
    elif cmd == SIMTRACE_MSGT_RESET: 
        print 'SIMTRACE_MSGT_RESET'
    else:    
        print 'Unknown SIMTRACE_MSGT cmd:%d' % (cmd)

if __name__ == "__main__":
    path = sys.argv[1]
    assert os.path.exists(path)
    with open(path,'rb') as f:
        num_simtrace_packets = 0
        while True:
            lenbuf = f.read(4)
            if len(lenbuf) != 4:
                break
            num_simtrace_packets +=1     
            (nbytes,) = struct.unpack('<I',lenbuf)
            simtrace_packet = f.read(nbytes)
            apdu_buf = simtrace_packet[simtrace_hdr_len:]
            hdr_buf = simtrace_packet[:simtrace_hdr_len]
            (cmd,flags,res0,res1) = struct.unpack(simtrace_hdr_fmt,hdr_buf)
            if True:
            #if apdu_buf.find('\x00\x88\x00')>=0:
                print '\n\n---simtrace packet:%d(%d bytes)---' % (num_simtrace_packets,nbytes)
                print_packet(cmd,flags,res0,res1,hdr_buf,apdu_buf)

