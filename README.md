# ip-enricher

Go client that classifies source IPs (currently from file, aspirationally from
nfqueue or packet capture) by ASN, AS Name, and BGP-advertised route (from MRT
file)

`ip-enricher` was originally based on a Go BGP server written by Rob Beverly
(@robertbeverly).

# Requirements and Dependencies

`ip-enricher` is developed and tested using Go version 1.22, although it should
work with any relatively modern version of Go (1.18+).

`ip-enricher` requires several libraries:

- `logrus`, for better logging
- `pflag`, for better commandline flags
- `github.com/seancfoley/ipaddress-go/ipaddr`, for the IP prefix tries 
- `github.com/jackyyf/go-mrt`, for MRT-formatted BGP RIB reading

# Building

To build `ip-enricher`, first ensure that you've installed the required libraries. From the `ip-enricher/` directory,

```bash
go mod tidy
```

Then, 

```bash
go build
```

This should produce a binary `ip-enricher`. If you are compiling for a different
architecture than the one you are building on, the build process may be slightly
more complicated.

# BGP RIB Data

[Routeviews](https://www.routeviews.org/) is a University of Oregon project that
collects BGP data by peering with a large number of Autonomous Systems (ASes) to
provide a global routing perspective. While many ASes operate Looking Glasses
(e.g. [Cogent](https://www.cogentco.com/en/looking-glass)) to inspect the view
of the BGP that a particular provider has, these Looking Glasses are (by design)
limited to the perspective of that provider. Routeviews aims to provide a global
routing perspective.

Routeview's [archive](https://archive.routeviews.org) contains BGP RIB dumps
that are updated every two hours. For instance, `archive.routeviews.org/bgpdata/2024.03/RIBS/` contains all of March 2024's RIB dumps in bz2-ed MRT format.

To properly identify which IPv4 and IPv6 IP addresses originate from which ASes,
you will need to download both an IPv4 RIB and an IPv6 RIB (e.g., from
`archive.routeviews.org/route-views6/bgpdata/2024.03/`) for the same time
interval.

Note that IPv4 and IPv6 RIB files for the same time interval will have the same
file name by default, so in order to manage them, you may want to rename the
`rib.` prefix of the IPv6 RIB to `ribv6.`. This is not strictly necessary,
especially if your IPs are only IPv4 or only IPv6.

# Usage

`ip-enricher` uses `pflag`, which produces a useful help menu with the `-h` or
`--help` flags.  

```bash
ip-enricher -h
> ./ip-enricher -h
  -a, --asn               Lookup ASNs for IP addresses
  -f, --file string       IP file to read
  -j, --json              Output in JSON format
  -o, --output string     Output filename
  -i, --ribFile strings   RIB files to read
  -v, --verbose           Verbose output
  -V, --version           Print version and exit
pflag: help requested
```

`ip-enricher` requires several arguments to run:

- a file of IP addresses to read (`-f/--file`). This file can contain both IPv4
and IPv6 addresses
- one or more BGP RIBs in bz2 MRT format, downloaded from Routeviews. These are
indicated with the `-i/--ribFile` flag.

`ip-enricher` can optionally output the results to a file using the `-j/--json` and `-o/--output` arguments, as demonstrated below.

With no output arguments, `ip-enricher` will write the results to stdout:

```bash
./ip-enricher -f test-ips.txt -i rib.20240318.0000.bz2 -i ribv6.20240318.0000.bz2
...example results...
2402:d000:800f:a::3:94f8        2402:d000::/32  9329                    
91.226.183.121  91.226.182.0/23 3223                    
2001:558:140:0:ffff:fffe:fff0:e 2001:558::/29   7922                    
13.38.186.144   13.36.0.0/14    16509                   
2a02:181f:1:123:34d8:daee:a38b:575b     2a02:1800::/24  6848                    
20.76.116.115   20.64.0.0/10    8075                    
104.83.67.230   104.83.64.0/20  16625                   
166.151.41.161  166.151.0.0/17  6167                    
23.55.241.132   23.55.241.0/24  20940                   
2a01:488:42:1000:50ed:84da:46:4fe6      2a01:488::/32   20773                   
2001:41d0:98:22ff:ffff:ffff:ffff:ff7f   2001:41d0::/32  16276                   
2a01:e0a:97e:4350::1    2a01:e0a:800::/39       12322                   
2003:cc:9fff:19e0:9a9b:cbff:feaa:c11a   2003::/19       3320      
...
```

where the first column is the IP address, the second column is the most specific
prefix announced in the BGP RIBs that contain that IP, and the third column is
the AS number of the AS that announced that prefix.

If no AS announces that IP (e.g., that IP is a bogon), the prefix will be given
as `N/A` and the ASN will be `-1`.

To write the results to a TSV file, add an output `-o` flag that specifies the
file you'd like to write to:

```bash
./ip-enricher -f test-ips.txt -i rib.20240318.0000.bz2 -i ribv6.20240318.0000.bz2 -o example-output.tsv
```

To write the results in JSON format, add a `-j/--json` flag to the previous
example. 

```bash
./ip-enricher -f test-ips.txt -i rib.20240318.0000.bz2 -i
ribv6.20240318.0000.bz2 -j -o example-output.json
...example output...
{"ip":"149.30.207.121","prefix":"149.30.207.0/24","asn":133199}
{"ip":"23.207.218.140","prefix":"23.207.218.0/23","asn":16625}
{"ip":"64.84.116.52","prefix":"64.84.116.0/22","asn":21743}
{"ip":"138.100.43.67","prefix":"138.100.0.0/16","asn":766}
{"ip":"37.139.24.252","prefix":"37.139.0.0/19","asn":14061}
{"ip":"114.33.30.51","prefix":"114.33.0.0/16","asn":3462}
{"ip":"54.215.185.51","prefix":"54.215.128.0/18","asn":16509}
{"ip":"2a04:ee41:4:b0f2::1","prefix":"2a04:ee40::/29","asn":15796}
{"ip":"240e:476:c0:8962::1","prefix":"240e:474::/30","asn":4134}
{"ip":"115.78.226.125","prefix":"115.78.224.0/21","asn":7552}
```

### Optional: Team Cymru AS name lookup

To enrich the IP addresses with additional AS information, we can use Team
Cymru's DNS-based ASN lookup service. This requires an Internet connection and
will make DNS requests.

For each IP address with a new ASN in the output, `ip-enricher` will (when the
`-a` flag is passed), do a DNS lookup to Team Cymru to get additional AS
information, including the AS name, the RIR, and the country code. This
information originates from WHOIS.

`ip-enricher` will cache the AS data for each ASN, so a file containing
10,000,000 records from a single ASN will cause only one DNS request to be sent
to Team Cymru.

This works with stdout or TSV output:
```bash
./ip-enricher -f test-ips.txt -i rib.20240318.0000.bz2 -i ribv6.20240318.0000.bz2 -o example-output.tsv -a
... example output
104.140.116.23	104.140.116.0/22	62904	US	arin	AS62904, US
2a0c:4182:16eb:fd65:5ce9:44a5:97f7:f418	2a0c:4182::/32	211027	RU	ripencc	RACKTECH, RU
82.146.60.30	82.146.56.0/21	29182	RU	ripencc	RU-JSCIOT, RU
2a01:e0a:5fc:8830::1	2a01:e0a:400::/39	12322	FR	ripencc	PROXAD, FR
116.204.20.243	116.204.0.0/18	55990	CN	apnic	HWCSNET Huawei Cloud Service data center, CN
23.12.1.200	23.12.0.0/19	16625	US	arin	AKAMAI-AS, US
...
```

and JSON output:

```bash
./ip-enricher -f test-ips.txt -i rib.20240318.0000.bz2 -i ribv6.20240318.0000.bz2 -j -o example-output-asn.json -a
...example output...
{"ip":"108.186.184.57","prefix":"108.186.0.0/16","asn":54600,"cc":"US","rir":"arin","name":"PEG-SV, US"}
{"ip":"2408:822a:3400:1059:4267:9bff:fe1a:a259","prefix":"2408:822a::/32","asn":4837,"cc":"CN","rir":"apnic","name":"CHINA169-BACKBONE CHINA UNICOM China169 Backbone, CN"}
{"ip":"104.140.116.23","prefix":"104.140.116.0/22","asn":62904,"cc":"US","rir":"arin","name":"AS62904, US"}
{"ip":"2a0c:4182:16eb:fd65:5ce9:44a5:97f7:f418","prefix":"2a0c:4182::/32","asn":211027,"cc":"RU","rir":"ripencc","name":"RACKTECH, RU"}
{"ip":"82.146.60.30","prefix":"82.146.56.0/21","asn":29182,"cc":"RU","rir":"ripencc","name":"RU-JSCIOT, RU"}
{"ip":"2a01:e0a:5fc:8830::1","prefix":"2a01:e0a:400::/39","asn":12322,"cc":"FR","rir":"ripencc","name":"PROXAD, FR"}

```

# Gotchas

If you run `ip-enricher` with an IP address type that has no corresponding BGP
RIB, all of that address type will not be found. That is, their prefix will be
listed as `N/A` and their ASN listed as `-1`. For instance, if a file containing
mixed IPv4 and IPv6 addresses is give as the input, but only an IPv6 RIB is
passed with `-i`, the output will fail to produce meaningful results for all
IPv4 IP addresses:

```bash
./ip-enricher -f test-ips.txt -i ribv6.20240318.0000.bz2
...example results...
111.94.253.38	N/A	-1			
150.60.251.207	N/A	-1			
2001:1c03:5800:0:85c8:7bb3:ccde:a4eb	2001:1c00::/24	33915			
66.148.122.75	N/A	-1			
196.243.240.60	N/A	-1			
13.126.114.131	N/A	-1			
62.221.215.41	N/A	-1			
164.138.22.92	N/A	-1			
2804:d41:31e:26f0::1	2804:d40::/28	7738			
2001:1c06:1c00:0:691b:3ca0:5b7d:763d	2001:1c00::/24	33915			
3.138.250.74	N/A	-1			
2a01:70:1:192::2	2a01:70::/32	25098			
23.49.165.193	N/A	-1	
```
