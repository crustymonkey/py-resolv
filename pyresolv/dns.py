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
    def lookup(self , query , qtype=QT_A , qclass=CL_IN , 
            qr=0 , opcode=OPC_QUERY , aa=0 , tc=0 , rd=1 , ra=0 ,
            rcode=RCD_OK):
        """
        Perform a lookup and return a dnsreqres.DnsResult object

        query:str       The actual item you are looking up, such as
                        "google.com"
        """
        pass
