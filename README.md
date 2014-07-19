CheckSSLBL
==========

Perl Script for Checking PCAPS against abuse.ch SSL Blacklist

Usage:

Pipe the output of ssldump to the CheckSSLBL.pl i.e.  
```ssldump -ANn -r dump.cap | perl CheckSSLBL.pl```  
```ssldump -ANn -i eth1 | perl CheckSSLBL.pl```
