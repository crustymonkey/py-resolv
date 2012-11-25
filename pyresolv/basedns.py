
import dnsreqres as drr
# Import all the constants
from . import *
import re , socket

# Basic checks here for ip
RE_IPV4 = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')

class BaseDNS(object):
    """
    The base DNS class
    """
    def __init__(self , defaultTimeout=3.0 , resolvers=[] , 
            resolvConf='/etc/resolv.conf' , useFirstOnly=True):
        """
        Initialize the library with the default timeout (can be 
        overridden in each request) and resolvers

        defaultTimeout:float    The time in seconds to timeout 
                                the request.
        resolvers:list[str]     The list of resolvers (IPs) to use
                                for lookups (these will be parsed
                                from resolv.conf if not specified)
        resolvConf:str          The path to the resolv.conf file.  This
                                will be parsed if the "resolvers" list
                                is empty
        useFirstOnly:bool       Just use the first resolver in the
                                list of resolvers either passed in
                                or in the resolv.conf file.  Otherwise,
                                all resolvers are tried simultaneously
                                and the first to respond is what is
                                returned.
        """
        self.defTO = float(defaultTimeout)
        self.resolvers = resolvers
        self.resolvConf = resolvConf
        self.useFirst = useFirstOnly
        # Map for resolver IP to address family
        self._resvMap = {}
        # list for requests
        self._reqs = []
        if not self.resolvers:
            self._parseResolvConf()
        self._validateResolvers()
        if not self.resolvers:
            # if we don't have resolver(s) at this point, throw an error
            raise MissingDataError('You must specify at least one valid '
                'resolver IP to use')

    def lookup(self , query , qtype=QT_A , timeout=None , qclass=CL_IN , 
            opcode=OPC_QUERY , rd=1):
        """
        Perform a lookup and return a dnsreqres.DnsResult object.  If 
        you want more information on the options, see RFC 1035

        query:str       The actual item you are looking up, such as
                        "google.com" qtype:int       
                        This should be one of the constants starting
                        with QT_  These are imported at all levels
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
        return self._doLookup(req , timeout)

    def a(self , query):
        """
        Shortcut to lookup an A record
        """
        return self.lookup(query)

    def aaaa(self , query):
        """
        Shortcut to lookup a AAAA record (ipv6)
        """
        return self.lookup(query , QT_AAAA)

    def cname(self , query):
        """
        Shortcut to lookup a CNAME record
        """
        return self.lookup(query , QT_CNAME)

    def mx(self , query):
        """
        Shortcut to lookup an MX record
        """
        return self.lookup(query , QT_MX)

    def txt(self , query):
        """
        Shortcut to lookup a TXT record
        """
        return self.lookup(query , QT_TXT)

    def soa(self , query):
        """
        Shortcut to lookup an SOA record
        """
        return self.lookup(query , QT_SOA)

    def ns(self , query):
        """
        Shortcut to lookup an NS record
        """
        return self.lookup(query , QT_NS)

    def ptr(self , query):
        """
        Shortcut to lookup a PTR record.  Note that this expects the
        query to be in the form of x.x.x.x.in-addr.arpa  Use "reverse()"
        to just use an IP addr instead
        """
        return self.lookup(query , QT_PTR)

    def reverse(self , query):
        """
        Your query here can be just an ip address, either v4 or v6 and
        the reversing of the address and domain will be appended
        and looked up for you automatically
        """
        family = socket.AF_INET
        suffix = 'in-addr.arpa'
        if ':' in query:
            # We presume this is a v6 addr
            family = socket.AF_INET6
            suffix = 'ipv6.arpa'
        # Create a byte list buffer
        bl = []
        try:
            # convert to a string
            ipStr = socket.inet_pton(family , query)
        except Exception , e:
            # We have an invalid IP specification
            raise ReqError('Your specification for a reverse has an invalid '
                'IP address %s: %s' % (query , str(e)))
        # We loop through the raw hex bytes here in reverse and convert 
        # them to decimal string values
        for i in ipStr[::-1]:
            bl.append(str(ord(i)))
        # Get the arpa str to lookup
        realQ = '%s.%s' % ('.'.join(bl) , suffix)
        return self.ptr(realQ)

    def axfr(self , query):
        """
        Shortcut to do an AXFR lookup
        """
        return self.lookup(query , QT_AXFR)

    def any(self , query):
        """
        Shortcut to do an ANY (ALL) query
        """
        return self.lookup(query , QT_ALL)

    def _getSock(self , resolver , timeout):
        s = socket.socket(socket.AF_INET , socket.SOCK_DGRAM)
        s.settimeout(float(timeout))
        s.connect((resolver , 53))
        return s

    def _parseResolvConf(self):
        """
        Parse the resolv.conf file for nameservers
        """
        fh = open(self.resolvConf)
        for line in fh:
            if line.lower().startswith('nameserver'):
                self.resolvers.append(line.strip().split()[1])
        fh.close()

    def _validateResolvers(self):
        """
        Make sure all the resolvers are valid IP addresses
        """
        for r in self.resolvers[:]:
            if RE_IPV4.match(r):
                if self._validIpv4(r):
                    # Map to an AF_INET
                    self._resvMap[r] = socket.AF_INET
                else:
                    # We have an invalid IPv4 addr, remove it from the
                    # resolver list
                    self.resolvers.remove(r)
            else:
                # We should have an IPv6 addr, validate it
                if self._validIpv6(r):
                    # Map to an AF_INET
                    self._resvMap[r] = socket.AF_INET6
                else:
                    # Remove an invalid IPv6 addr
                    self.resolvers.remove(r)

    def _validIp(self , ip , family):
        try:
            socket.inet_pton(family , ip)
        except socket.error:
            return False
        return True

    def _validIpv4(self , ip):
        """
        Validates the ip against the socket library.  If there is an
        error, it's invalid
        """
        return self._validIp(ip , socket.AF_INET)

    def _validIpv6(self , ip):
        """
        Validates the ip against the socket library.  If there is an
        error, it's invalid
        """
        return self._validIp(ip , socket.AF_INET6)

    def _doLookup(self):
        # This MUST be overridden in a subclass
        raise NotImplementedError('You must override this in a subclass')
