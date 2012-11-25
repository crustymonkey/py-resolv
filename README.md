# py-resolv #

## NOT COMPLETE ##
If you are reading this, then I have not completed this library yet.  I
decided to add it to github first and finish it second.

## Description ##
A python DNS library with support for synchronous and asynchronous lookups

The goal here is to provide a simple, clean interface for both blocking
and non-blocking DNS lookups.  The code and standards here are based on
RFC 1035: http://www.ietf.org/rfc/rfc1035.txt

## Full Disclosure ##
A fair amount of code in pyresolv.dnsreqres was used from the pydns
library (http://pydns.sourceforge.net/) either directly or as reference.
At the time I started writing this (a few years ago), I needed a simple, 
clean abstraction for packet creation and dissection.  I recently
decided to tack on the lookup handling portions of these previously
written packet creation classes (see pyresolv.dnsreqres).

## IPv6 ##
At the time of this writing, I wanted to, at least theoretically, support
IPv6 resolvers.  If you are reading this, the IPv6 has not actually been
tested (blame Comcast and my laziness).  If you can competently test
IPv6, please do, and submit bugs on github.

## Examples ##
There is example code in the examples directory.  

## Documentation ##
You can use pydoc for library docs:

* pydoc pyresolv
* pydoc pyresolv.dns
* pydoc pyresolv.adns
* pydoc pyresolv.dnsreqres

There will also be documentation on http://stuffivelearned.org eventually.
I will replace this paragraph with a direct link when that documentation
is completed
