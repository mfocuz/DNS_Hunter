## DNS_Hunter
DNS enumeration tool.
Main idea of yet another DNS discovery tool is hashcat feature with bruting by masks.

## Installation
From DNS_Hunter directory:
```
$ sudo cpan -i Module::CPANfile
$ sudo cpanm --installdeps .
```
*Note:* Sudo is required for default CPAN configuration due to it stores Perl modules in /usr directory.

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
  --max-dns-gen <number>\tNumber of domains to generate before resolution
  --no-resolve only generates domain names w/o resolving

Mask syntax:
  \t?c - char\n\t?d - digit\n\t{sub} - subdomain\n\tAny bare chars can be used as is
  
  Example: ./dns_hunter --domain example.com --output-file /tmp/result --sub-list /tmp/sub.list
    --mask '?c?c-{sub}-?d?d-{sub}-anywords'
```
  
