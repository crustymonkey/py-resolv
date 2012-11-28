"""
Asynchronous DNS library
"""

import dnsreqres as drr
from basedns import BaseDNS
from . import *
import Queue
import threading , socket , select

class ADNS(BaseDNS , threading.Thread):
    """
    Asynchronous DNS library
    """
    def __init__(self , defaultTimeout=3.0 , resolvers=[] ,
            resolvConf='/etc/resolv.conf' , useFirstOnly=True):
        BaseDNS.__init__(self , defaultTimeout , resolvers , resolvConf , 
            useFirstOnly)
        threading.Thread.__init__(self)
        # Create a thread-safe queue
        self._q = Queue.Queue()
        # Need a map for request ids -> requests
        self._reqMap = {}
        # Die when the program ends
        self.daemon = True
        # Create a close event for the main event loop
        self._close = threading.Event()
        self._socks = []
        self._openSockets()
        self.start()

    def run(self):
        """
        The main event loop
        """
        pMask = select.EPOLLIN | select.EPOLLPRI
        p = select.poll()
        fdMap = {}
        # Register the socket file descriptors in the poll object
        for s in self._socks:
            fd = s.fileno()
            p.register(fd , pMask)
            fdMap[fd] = sock
        # Start the main loop
        while True:
            new = None
            try:
                new = self._q.get_nowait()
            except Queue.Empty:
                # Nothing waiting, pass
                pass

    def close(self):
        """
        Set the close event
        """
        self._close.set()

    def _openSockets(self):
        for resolver in self.resolvers:
            # Get a socket connection for each resolver
            self._socks.append(self._getSock(resolver , self._defTO))
            if self.useFirst: break

    def _doLookup(self , req , timeout):
        if not self._close.isSet():
            # Add a tuple of (req , timeout) to the queue
            self._q.put((req , timeout))
