
class BaseDNS(object):
    """
    The base DNS class
    """
    def __init__(self , defaultTimeout=3.0 , resolvers=[] , 
            resolvConf='/etc/resolv.conf'):
        """
        Initialize the library with the default timeout (can be 
        overridden in each request) and resolvers

        defaultTimeout:float    The time in seconds to timeout 
                                the request
        resolvers:list[str]     The list of resolvers to use for 
                                lookups (these will be parsed
                                from resolv.conf if not specified)
        resolvConf:str          The path to the resolv.conf file.  This
                                will be parsed if the "resolvers" list
                                is empty
        """
        self.defTO = defaultTimeout
        self.resolvers = resolvers
        self.resolvConf = resolvConf
        # list for requests
        self._reqs = []
        if not self.resolvers:
            self._parseResolvConf()

    def _parseResolvConf(self):
        """
        Parse the resolv.conf file for nameservers
        """
        fh = open(self.resolvConf)
        for line in fh:
            if line.lower().startswith('nameserver'):
                self.resolvers.append(line.strip().split()[1])
        fh.close()
