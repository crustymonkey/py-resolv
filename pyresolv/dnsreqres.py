#!/usr/bin/env python

__svnversion__ = '$Id$'

import struct , random
from errors import ReqError , ResError
from cStringIO import StringIO
from . import *

__all__ = ['DnsRequest' , 'DnsResult']

"""
For more information on this, see RFC 1035

To give credit where credit is due, some of the code here is based on
the pydns library:  http://pydns.sourceforge.net
"""

class DnsRequest(object):
    def __init__(self , qname , qtype=QT_A , qclass=CL_IN , qr=0 , 
            opcode=OPC_QUERY , aa=0 , tc=0 , rd=1 , ra=0 , rcode=RCD_OK):
        self.buf = StringIO()
        self.qname = qname
        self.qtype = int(qtype)
        self.qclass = int(qclass)
        self.id = self._getId()
        self.qr = int(qr)
        self.opcode = int(opcode)
        self.aa = int(aa)
        self.tc = int(tc)
        self.rd = int(rd)
        self.ra = int(ra)
        self.z = 0
        self.rcode = int(rcode)
        self.qdcount = 1
        self.ancount = 0
        self.nscount = 0
        self.arcount = 0
        # Process the above to generate a buffer
        self._addHeader()
        self._addQuestion()
    
    def __str__(self):
        return self.getBuf()

    def __del__(self):
        try:
            self.close()
        except:
            pass
        
    def getBuffer(self):
        return self.getBuf()
    
    def getBuf(self):
        return self.buf.getvalue()

    def close(self):
        """
        Destroys the buffer for cleanup
        """
        try:
            self.buf.close()
        except:
            pass
    
    def _getId(self):
        return random.randint(0 , 65535)
    
    def _get16bit(self , n):
        return struct.pack('!H' , n)
    
    def _getName(self , name):
        ret = ''
        for part in name.split('.'):
            if part:
                part = part.encode('utf8')
                l = len(part)
                if l > 63:
                    raise ReqError('The length of part, %s, ' % part +
                        'is limited to 63 characters')
                ret += chr(l) + part
        ret += '\0'
        return ret
    
    def _addHeader(self):
        self.buf.write(self._get16bit(self.id))
        self.buf.write(self._get16bit((self.qr & 1) << 15 | 
                (self.opcode & 15) << 11 | (self.aa & 1) << 10 |
                (self.tc & 1) << 9 | (self.rd & 1) << 8 |
                (self.ra & 1) << 7 | (self.z & 7) << 4 | (self.rcode & 15)))
        self.buf.write(self._get16bit(self.qdcount))
        self.buf.write(self._get16bit(self.ancount))
        self.buf.write(self._get16bit(self.nscount))
        self.buf.write(self._get16bit(self.arcount))
        
    def _addQuestion(self):
        self.buf.write(self._getName(self.qname))
        self.buf.write(self._get16bit(self.qtype))
        self.buf.write(self._get16bit(self.qclass))

class DnsResult(object):
    def __init__(self , rawBuf):
        self.rawBuf = rawBuf
        self._bp = 0    # Pointer to keep track of current location in buf
        self.qname = ''
        self.qtype = 0
        self.qclass = 0
        self.id = -1
        self.qr = 0
        self.opcode = 0
        self.aa = 0
        self.tc = 0
        self.rd = 0
        self.ra = 0
        self.z = 0
        self.rcode = 0
        self.qdcount = 0
        self.ancount = 0
        self.nscount = 0
        self.arcount = 0
        self.answers = []
        self.authority = []
        self.additional = []
        try:
            self._extractHeader()
            self._extractQuestion()
        except:
            raise ResError('Invalid DNS result')
        # Convenience Error stuff
        self.errno = self.rcode
        self.error = self._getErrStr()
        if self.rcode == RCD_OK:
            # Get the answer
            try:
                self._extractData(self.ancount , self.answers)
                self._extractData(self.nscount , self.authority)
                self._extractData(self.arcount , self.additional)
            except:
                raise ResError('Invalid DNS result')
        
    def _get16bit(self , s=None):
        if s == None:
            s = self._getBytes(2)
        return struct.unpack('!H' , s)[0]
    
    def _get32bit(self , s=None):
        if s == None:
            s = self._getBytes(4)
        return struct.unpack('!L' , s)[0]
    
    def _getBytes(self , num):
        end = self._bp + num
        bytes = self.rawBuf[self._bp:end]
        self._bp = end
        return bytes
    
    def _getErrStr(self):
        if self.errno == RCD_OK:
            return 'OK'
        elif self.errno == RCD_FRMT_ERR:
            return 'FORMATERROR'
        elif self.errno == RCD_SERVFAIL:
            return 'SERVFAIL'
        elif self.errno == RCD_NAME_ERR:
            return 'NXDOMAIN'
        elif self.errno == RCD_NOT_IMPL:
            return 'NOTIMPLEMENTED' 
        elif self.errno == RCD_REFUSED:
            return 'REFUSED'
        else:
            return 'UNKNOWNERROR'
        
    def _getSOA(self , data):
        mname , off = self._getName(data=data , retOffset=True)
        rname , off = self._getName(off , data , True)
        serial = self._get32bit(data[off:off+4])
        off = off + 4
        refresh = self._get32bit(data[off:off+4])
        off = off + 4
        retry = self._get32bit(data[off:off+4])
        off = off + 4
        expire = self._get32bit(data[off:off+4])
        off = off + 4
        min = self._get32bit(data[off:off+4])
        return (mname , rname , serial , refresh , retry , expire , min)
        
    def _getName(self , offset=-1 , data=None , retOffset=False):
        qname = ''
        cp = offset
        if data and cp == -1:
            cp = 0
        while True:
            i = 0
            if data:
                i = ord(data[cp:cp+1])
                cp += 1
            elif cp > -1:
                i = ord(self.rawBuf[cp:cp+1])
                cp += 1
            else:
                i = ord(self._getBytes(1))
            if i & 0xC0 == 0xC0:
                # Pointer, get the next byte
                j = 0
                if data:
                    j = ord(data[cp:cp+1])
                    cp += 1
                elif cp > -1:
                    j = ord(self.rawBuf[cp:cp+1])
                    cp += 1
                else:
                    j = ord(self._getBytes(1))
                pOffset = ((i << 8) | j) & ~0xC000
                dom = self._getName(pOffset)
                if qname:
                    qname += '.%s' % dom
                else:
                    qname = dom
                if retOffset:
                    return (qname , cp)
                else:
                    return qname
            elif i == 0:
                if retOffset:
                    return (qname , cp)
                else:
                    return qname
            else:
                chunk = ''
                if data:
                    chunk = data[cp:cp+i]
                    cp += i
                elif cp > -1:
                    chunk = self.rawBuf[cp:cp+i]
                    cp += i
                else:
                    chunk = self._getBytes(i)
                if qname:
                    qname = '%s.%s' % (qname , chunk)
                else:
                    qname = chunk
                    
    def _procRawData(self , data , qtype , cl):
        if qtype in (QT_CNAME , QT_MB , QT_MD , QT_MF , QT_MG , QT_MR ,
                QT_NS , QT_PTR):
            return self._getName(data=data)
        elif qtype == QT_MX:
            pref = self._get16bit(data[:2])
            dom = self._getName(data=data[2:])
            return (pref , dom)
        elif qtype == QT_A:
            ip = ''
            for i , c in enumerate(data):
                if i < 3:
                    ip += '%d.' % ord(c)
                else:
                    ip += str(ord(c))
            return ip
        elif qtype in (QT_NULL , QT_TXT):
            return data
        elif qtype == QT_SOA:
            return self._getSOA(data)
        elif qtype == QT_MINFO:
            rmailbx , off = self._getName(data=data , retOffset=True)
            emailbx = self._getName(off , data)
            return (rmailbx , emailbx)
        elif qtype == QT_AAAA:
            ipv6 = ''
            for i , c in enumerate(data):
                ipv6 += hex(ord(c))
                if i % 2 == 0 and i > 0 and i < 15:
                    ipv6 += ':'
            return ipv6
        else:
            raise ReqError('Unsupported query type for domain %s: %d' % 
                    (self.qname , qtype))
        
    def _extractHeader(self):
        self.id = self._get16bit()
        flags = self._get16bit()
        self.qr = (flags >> 15) & 1
        self.opcode = (flags >> 11) & 15
        self.aa = (flags >> 10) & 1
        self.tc = (flags >> 9) & 1
        self.rd = (flags >> 8) & 1
        self.ra = (flags >> 7) & 1
        self.z = (flags >> 4) & 7
        self.rcode = flags & 15
        self.qdcount = self._get16bit()
        self.ancount = self._get16bit()
        self.nscount = self._get16bit()
        self.arcount = self._get16bit()
        
    def _extractQuestion(self):
        self.qname = self._getName()
        self.qtype = self._get16bit()
        self.qclass = self._get16bit()
    
    def _extractData(self , count , l):
        for i in xrange(count):
            name = self._getName()
            qtype = self._get16bit()
            cl = self._get16bit()
            ttl = self._get32bit()
            rdlen = self._get16bit()
            rawData = self._getBytes(rdlen)
            data = self._procRawData(rawData , qtype , cl)
            l.append((name , qtype , cl , ttl , data))
            
    def __str__(self):
        return repr(self.answers)

def test():
    import socket , time , sys
    domains = (
        'gettilted.com' ,
        'www.google.com' ,
    )
    s = socket.socket(socket.AF_INET , socket.SOCK_DGRAM)
    s.settimeout(1.0)
    s.connect(('localhost' , 53))
    for d in domains:
        time.sleep(0.01)
        req = DnsRequest(d , QT_A)
        s.send(req.getBuf())
        try:
            buf = s.recv(65535)
        except socket.timeout:
            print >> sys.stderr , 'Timed out getting %s' % d
        res = DnsResult(buf)
        print res

if __name__ == '__main__':
    test()
