
import re

# Basic checks here for ip
RE_IPV4 = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')

class BaseDNS(object):
    """
    The base DNS class
    """
    def __init__(self , defaultTimeout=3.0 , resolvers=[] , 
            resolvConf='/etc/resolv.conf' , useFirstResolver=True):
        """
        Initialize the library with the default timeout (can be 
        overridden in each request) and resolvers

        defaultTimeout:float    The time in seconds to timeout 
                                the request.  This will be applied
                                to all resolvers if if useFirstResolver
                                if False.  ex.: if you have 3 resolvers
                                and you set the timeout to 4, the
                                request can take up to 12 seconds
        resolvers:list[str]     The list of resolvers (IPs) to use
                                for lookups (these will be parsed
                                from resolv.conf if not specified)
        resolvConf:str          The path to the resolv.conf file.  This
                                will be parsed if the "resolvers" list
                                is empty
        useFirstResolver:bool   Just use the first resolver in the
                                list of resolvers either passed in
                                or in the resolv.conf file.  Do not
                                try anything else.
        """
        self.defTO = defaultTimeout
        self.resolvers = resolvers
        self.resolvConf = resolvConf
        self.useFirst = useFirstResolver
        # list for requests
        self._reqs = []
        if not self.resolvers:
            self._parseResolvConf()
        self._validateResolvers()
        if not self.resolvers:
            # if we don't have resolver(s) at this point, throw an error
            raise MissingDataError('You must specify at least one valid '
                'resolver IP to use')

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
            if RE_IPV4.match(r) and not self._validIpv4(r):
                # We have an invalid IPv4 addr, remove it from the
                # resolver list
                self.resolvers.remove(r)
            else:
                # We should have an IPv6 addr, validate it
                if not self._validIpv6(r):
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
