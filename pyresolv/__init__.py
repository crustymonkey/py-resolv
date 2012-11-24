
__version__ = '0.1.0'

# Constants
###########

# Opcodes
OPC_QUERY = 0
OPC_IQUERY = 1
OPC_STATUS = 2

# Rcodes
RCD_OK = 0
RCD_FRMT_ERR = 1
RCD_SERVFAIL = 2
RCD_NAME_ERR = 3
RCD_NOT_IMPL = 4
RCD_REFUSED = 5

# QTypes
QT_A = 1
QT_NS = 2
QT_MD = 3       # Obsolete, use MX
QT_MF = 4       # Obsolete, use MX
QT_CNAME = 5
QT_SOA = 6
QT_MB = 7       # Experimental, do not use
QT_MG = 8       # Experimental, do not use
QT_MR = 9       # Experimental, do not use
QT_NULL = 10    # Experimental, do not use
QT_WKS = 11
QT_PTR = 12
QT_HINFO = 13
QT_MINFO = 14
QT_MX = 15
QT_TXT = 16
QT_AAAA = 28
QT_AXFR = 252
QT_MAILB = 253
QT_MAILA = 254  # Obsolete, see MX
QT_ALL = 255

# Classes
CL_IN = 1
CL_CS = 2       # Obsolete
CL_CH = 3
CL_HS = 4
CL_ANY = 255

