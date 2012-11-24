"""
Synchronous DNS client library
"""

import dnsreqres as drr
from basedns import BaseDNS
from errors import TimeoutError
# Get all the constants in init
from . import *

class DNS(BaseDNS):
    """
    This class will perform synchronous (blocking) DNS lookups
    """
    def lookup(self , query , qtype=QT_A , timeout=None , qclass=CL_IN , 
            opcode=OPC_QUERY , rd=1):
        """
        Perform a lookup and return a dnsreqres.DnsResult object.  If 
        you want more information on the options, see RFC 1035

        query:str       The actual item you are looking up, such as
                        "google.com"
        qtype:int       This should be one of the constants starting
                        QT_  These are imported at all levels
        timeout:float   This should be a timeout in seconds.
                        defaultTimeout will be used if not specified
                        here
        opcode:int      A flag for originator of the query.  Use
                        one of the OPC_ constants
        rd:int          A flag (0 or 1) whether recursion is desired
        """
        # Get a request object
        req = drr.DnsRequest(query , qtype=qtype , qclass=qclass , 
            opcode=opcode , rd=rd)
        if timeout is None:
            timeout = self.defTO
        
