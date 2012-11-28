"""
Synchronous DNS client library
"""

import dnsreqres as drr
from basedns import BaseDNS
from errors import TimeoutError , ResError , ReqError
# Get all the constants in init
from . import *
import select

class DNS(BaseDNS):
    """
    This class will perform synchronous (blocking) DNS lookups
    """
    def batch(self , batchList , timeout=None):
        """
        Perform a batch of lookups and return a list of results in the
        form of (dnsreqres.DnsRequest , dnsreqres.DnsResult).  The
        result will be an Exception object if an exception occurs 
        for that lookup.

        batchlist:list[list|DnsRequest]     This should be a list
                        of either dsnreqres.DnsRequest objects or
                        a list/tuple of (query , qtype).  If you want
                        to use other options, you should use a list
                        of DnsRequest objects
        timeout:float   Timeout in seconds for EACH of the requests
        """
        if timeout is None:
            timeout = self.defTO
        todo = []
        ret = []
        # Loop through the list and add DnsRequest objects to the
        # todo list, converting normal requests as necessary
        for item in batchList:
            if not isinstance(item , drr.DnsRequest):
                item = drr.DnsRequest(*item)
            todo.append(item)
        for req in todo:
            res = None
            try:
                res = self._doLookup(req , timeout)
            except Exception , e:
                res = e
            ret.append((req , res))
        return ret

    def _doLookup(self , req , timeout):
        """
        Performs the actual lookup(s), handling all the socket 
        connections
        """
        ret = None
        timeout = float(timeout)
        mask = select.EPOLLIN | select.EPOLLPRI
        fdMap = {}
        p = select.poll()
        for resolver in self.resolvers:
            # Send the request to all resolvers
            sock = self._getSock(resolver , timeout)
            sock.sendall(req.getBuf())
            # Close the buffer and free the memory used
            req.close()
            fd = sock.fileno()
            p.register(fd , mask)
            fdMap[fd] = sock
            if self.useFirst: break
        res = p.poll(timeout)
        if res:
            # Get the first result in the list
            fd , event = res[0]
            sock = fdMap[fd]
            packet = sock.recv(65535)
            ret = drr.DnsResult(packet)
        # Close all the sockets
        for s in fdMap.itervalues():
            s.close()
        if ret.id != req.id:
            # Make sure the ids match
            raise ResError('Result id, %d, does not match ' % ret.id +
                'request id, %d. Possible forgery' % req.id)
        if not res:
            # Timed out
            tried = []
            if self.useFirst:
                tried.append(self.resolvers[0])
            else:
                tried = self.resolvers
            raise TimeoutError('Hit timeout of %f when querying %r' % 
                (timeout , tried))
        return ret
