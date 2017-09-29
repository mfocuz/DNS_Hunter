## DNS_Hunter
DNS enumeration tool.
Main idea of yet another DNS discovery tool is hashcat feature with bruting by masks.

## TODO
Please pay attention that only long options supported. Sorry for that, will fix later.

## Installation
From DNS_Hunter directory (Tested on linux):
```
$ sudo cpan -i Module::CPANfile
$ sudo cpanm --installdeps .
```
*Note:* Sudo is required for default CPAN configuration due to it stores Perl modules in /usr directory.

*Note2:* In case you have issue with AnyEvent::DNS installation, please try to install it manually with cpan
```
$cpan -i AnyEvent::DNS
```

## Options

```
Required options:
  --domain <domain name>                - domain address to brute
  --output-file </path/to/file>         - file to save results
 
One of the following bruting option required(or both can be used):
  --mask <mask>                         - mask for bruting
  --sub-list </path/to/subdomain/list>  - subdomain list

Optional parameters:
  --uniq <number> (default:5)           - Uniq IP address threshold
  --max-dns-query <number> (default:10) - Number of parallel DNS resolutions
  --max-dns-gen <number>                - Number of domains to generate before resolution
  --no-resolve                          - Only generates domain names w/o resolving
  --leet                                - Replace chars with 1337 numbers!

Mask syntax:
  ?c - char
  ?d - digit
  {sub} - subdomain 
  Any bare chars can be used as is.
  
  Example: ./dns_hunter.pl --domain example.com --output-file /tmp/result --sub-list sub_list_for_test.txt
    --mask '?c{sub}-?d{sub}-anywords'
```
  
