# Project 9 - Honeypot

Time spent: 20 hours spent in total

> Objective: Create a Honeypot on Google Cloud

## Lab
### Milestone 0
- root@kali:~# ifconfig
- eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
-         *inet 10.0.2.15*  netmask 255.255.255.0  broadcast 10.0.2.255
-         inet6 fe80::a00:27ff:fe4f:92a5  prefixlen 64  scopeid 0x20<link>
-         *ether 08:00:27:4f:92:a5*  txqueuelen 1000  (Ethernet)
-         RX packets 9510  bytes 11218368 (10.6 MiB)
-         RX errors 0  dropped 0  overruns 0  frame 0
-         TX packets 5834  bytes 596797 (582.8 KiB)
-         TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

- lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536-
-         *inet 127.0.0.1*  netmask 255.0.0.0
-         inet6 ::1  prefixlen 128  scopeid 0x10<host>
-         loop  txqueuelen 1000  (Local Loopback)
-         RX packets 322  bytes 18798 (18.3 KiB)
-         RX errors 0  dropped 0  overruns 0  frame 0
-         TX packets 322  bytes 18798 (18.3 KiB)
-         TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

What is your primary interface's IP address? Is it different from your public IP? Why or why not?
*10.0.2.15 this is the IP address of the primary ethernet interface. The address is a RFC1918 address and networking set to NAT. The public IP is set by the ISP and not reflected here.*
What is the MAC address of your primary interface?
*08:00:27:4f:92:a5 is the MAC address.*
Identify and understand your loopback interface
*lo is the loopback. Note the 127.0.0.1*

*What is the IP address of codepath.com?
What is the IP address of google.com?*
- root@kali:~# ping codepath.com
- PING *codepath.com (198.58.125.217)* 56(84) bytes of data.
- 64 bytes from thecodepath.com (198.58.125.217): icmp_seq=1 ttl=51 time=57.8 ms
- 64 bytes from thecodepath.com (198.58.125.217): icmp_seq=2 ttl=51 time=58.6 ms
- ^C
- --- codepath.com ping statistics ---
- 2 packets transmitted, 2 received, 0% packet loss, time 1001ms
- rtt min/avg/max/mdev = 57.895/58.284/58.673/0.389 ms
- root@kali:~# ping google.com
- PING *google.com (216.58.194.110)* 56(84) bytes of data.
- 64 bytes from dfw06s48-in-f110.1e100.net (216.58.194.110): icmp_seq=1 ttl=51 time=58.0 ms
- 64 bytes from dfw06s48-in-f110.1e100.net (216.58.194.110): icmp_seq=2 ttl=51 time=59.0 ms
- ^C
- --- google.com ping statistics ---
- 2 packets transmitted, 2 received, 0% packet loss, time 1001ms
- rtt min/avg/max/mdev = 58.063/58.549/59.036/0.543 ms
- root@kali:~# ping google.com
- PING google.com (216.58.194.110) 56(84) bytes of data.
- 64 bytes from dfw06s48-in-f14.1e100.net (216.58.194.110): icmp_seq=1 ttl=51 time=58.6 ms
- ^C
- --- google.com ping statistics ---
- 1 packets transmitted, 1 received, 0% packet loss, time 0ms
vrtt min/avg/max/mdev = 58.625/58.625/58.625/0.000 ms

*Why would the IP address of google.com change between runs or from different locations?*
Because Google has multiple servers with multiple IPs for failover protection and load balancing based on location.

*Using the IP for codepath.com from the previous, pass it to nslookup
Does the domain returned from nslookup match? If not, why not?*
- root@kali:~# nslookup 198.58.125.217
- 217.125.58.198.in-addr.arpa	name = thecodepath.com.
- root@kali:~# nslookup codepath.com
- Server:		192.168.1.254
- Address:	192.168.1.254#53

- Non-authoritative answer:
- Name:	codepath.com
- Address: 198.58.125.217

- It appears from the GoDaddy registrations and results that thecodepath.com. is the larger domain under which codepath.com and specifically the redirection to the www.codepath.com web server is handled. The DNS authoritative nameserver may be in thecodepath.com. domain but the two domains are linked.


*Compare the traceroutes for codepath.com and google.com
How many of the hops are the same? What accounts for this?
Which has more hops? What accounts for the difference?*
- 5 Hops are the same. The path to Google.com is longer. The difference is likely due to the greater complexity of Google's network and the routing infrastructure which provides failover and load balancing.

- $ traceroute codepath.com
- traceroute to codepath.com (198.58.125.217), 64 hops max, 52 byte packets

- 5 hops the same

 - 6  ggr2.la2ca.ip.att.net (12.122.128.97)  31.327 ms  28.104 ms  31.476 ms
 - 7  las-bb1-link.telia.net (80.239.193.213)  29.512 ms  30.766 ms  28.552 ms
-  8  las-b24-link.telia.net (62.115.136.47)  31.423 ms  29.669 ms
-     dls-b21-link.telia.net (62.115.123.136)  70.247 ms
-  9  dls-b22-link.telia.net (62.115.137.107)  71.500 ms  68.751 ms  76.354 ms
- 10  linode-ic-321020-dls-b22.c.telia.net (213.248.68.159)  69.594 ms  73.711 ms  70.377 ms
- 11  45.79.12.7 (45.79.12.7)  70.686 ms
-     45.79.12.5 (45.79.12.5)  72.261 ms
-     45.79.12.7 (45.79.12.7)  70.892 ms
- 12  thecodepath.com (198.58.125.217)  72.110 ms  72.167 ms  69.392 ms
- $ traceroute google.com
- traceroute to google.com (216.58.194.110), 64 hops max, 52 byte packets

- 5 hops the same

 - 6  12.122.104.117 (12.122.104.117)  29.800 ms  32.886 ms  26.632 ms
 - 7  12.255.10.166 (12.255.10.166)  28.111 ms  26.647 ms  27.279 ms
 - 8  108.170.247.147 (108.170.247.147)  27.668 ms
-     108.170.247.212 (108.170.247.212)  31.020 ms
-     108.170.247.243 (108.170.247.243)  31.657 ms
-  9  108.170.230.123 (108.170.230.123)  28.424 ms
-     108.170.234.214 (108.170.234.214)  31.618 ms
-     108.170.225.120 (108.170.225.120)  29.179 ms
- 10  108.170.247.244 (108.170.247.244)  33.858 ms
-     108.170.247.147 (108.170.247.147)  29.524 ms
-     108.170.247.244 (108.170.247.244)  38.293 ms
- 11  108.170.234.41 (108.170.234.41)  28.237 ms
-     108.170.230.123 (108.170.230.123)  27.982 ms
-     108.170.234.124 (108.170.234.124)  27.696 ms
- 12  216.239.46.128 (216.239.46.128)  59.147 ms
-     108.170.252.129 (108.170.252.129)  61.444 ms
-     216.239.46.22 (216.239.46.22)  59.358 ms
- 13  108.170.228.90 (108.170.228.90)  59.207 ms
-     108.170.230.109 (108.170.230.109)  72.076 ms  61.462 ms
- 14  dfw06s48-in-f110.1e100.net (216.58.194.110)  58.945 ms  58.819 ms
-     108.170.252.129 (108.170.252.129)  60.086 ms

*What's one thing that makes telnet insecure?
Can you telnet to codepath.com? What port is open and why?*

- Telnet traffic is unencrypted. 80 (http) is open as is 22 (ssh). Neither telnet (23) nor FTP (21) are open.

- root@kali:~# telnet codepath.com 80
- Trying 198.58.125.217...
- Connected to codepath.com.
- Escape character is '^]'.
- GET
- HTTPConnection closed by foreign host.
- root@kali:~# telnet codepath.com 23
- Trying 198.58.125.217...
- telnet: Unable to connect to remote host: Connection refused
- root@kali:~# telnet codepath.com 21
- Trying 198.58.125.217...
- telnet: Unable to connect to remote host: Connection refused
- root@kali:~# telnet codepath.com 22
- Trying 198.58.125.217...
- Connected to codepath.com.
- Escape character is '^]'.
- SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.3

- Protocol mismatch.
- Connection closed by foreign host.


*curl vs wget: Identify some differences between the two.*
- wget is simpler standalone application to use, more focused on HTTP/S and FTP traffic with the ability to recursively download. curl has a full library behind it, is more powerful and supports more protocols. Also, curl offers upload and sending capabilities while wget only offers plain HTTP POST support.

*Which would you be more likely to use for interacting with a RESTful API from the command line?*
- curl, because of its powerful library and ability to build requests with finer granularity.

*Which support recursive downloading?*
- wget

*Which are you more likely to find pre-installed on a Linux OS?*
- Based on searching the web, likely wget

*What is the syntax for each for downloading a file to the current directory?*
- wget ftp://somesite.com/somefile.txt

- curl -O ftp://somesite.com/someotherfile.png


*Why is key authentication preferred to passwords?*
- Because there is no need to create and remember strong passwords. Instead, the key file with the strong key is stored on the device, allowing the device to authenticate as opposed to the individual. The admin has control over the distribution of the key file and revocation.

*What is the syntax for copying a file from a local folder to a remote one?*
- Using scp over port 22: scp <filepath> user@server:<filepath>

### Milestone 1
- root@kali:~# nmap -sV localhost

- Starting Nmap 7.60 ( https://nmap.org ) at 2018-05-28 00:16 EDT
- Nmap scan report for localhost (127.0.0.1)
- Host is up (0.0000060s latency).
- Other addresses for localhost (not scanned): ::1
- Not shown: 998 closed ports
- PORT    STATE SERVICE     VERSION
- 139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
- 445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
- Service Info: Host: KALI

- Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
-
*CANNOT DO THIS ON THE SCHOOL NETWORK, VM NETWORK INSTEAD*
- root@kali:~# nmap -sS 192.168.56.0/24

- Starting Nmap 7.60 ( https://nmap.org ) at 2018-05-28 00:25 EDT
- Nmap scan report for 192.168.56.5
- Host is up (0.00033s latency).
- Not shown: 842 closed ports, 154 filtered ports
- PORT     STATE SERVICE
- 22/tcp   open  ssh
- 3306/tcp open  mysql
- 5432/tcp open  postgresql
- 8080/tcp open  http-proxy
- MAC Address: 08:00:27:29:85:AE (Oracle VirtualBox virtual NIC)

- Nmap scan report for 192.168.56.2
- Host is up (0.000021s latency).
- Not shown: 998 closed ports
- PORT    STATE SERVICE
- 139/tcp open  netbios-ssn
- 445/tcp open  microsoft-ds

- Nmap done: 256 IP addresses (2 hosts up) scanned in 33.10 seconds

![](https://github.com/dallens/CodepathWeek9Honeypots/blob/master/w9_m1netcat.png)
### Milestone 2
- root@kali:~# sudo tcpdump -n dst host 198.58.125.217
- tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
- listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
- 00:34:30.414246 IP 10.0.2.15.35100 > 198.58.125.217.80: Flags [S], seq 2357101203, win 29200, options [mss 1460,sackOK,TS val 1034852377 ecr 0,nop,wscale 7], length 0
- 00:34:30.471670 IP 10.0.2.15.35100 > 198.58.125.217.80: Flags [.], ack 13061, win 29200, length 0
- 00:34:30.472011 IP 10.0.2.15.35100 > 198.58.125.217.80: Flags [P.], seq 0:312, ack 1, win 29200, length 312: HTTP: GET / HTTP/1.1
.
.
.
.
.
- 710 packets captured
- 710 packets received by filter
- 0 packets dropped by kernel

*Mostly Javascript and image files.*

- root@kali:~# sudo tcpdump -n dst host 130.211.189.113
- tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
- listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
- 00:41:39.619081 IP 10.0.2.15.33720 > 130.211.189.113.443: Flags [S], seq 3201374923, win 29200, options [mss 1460,sackOK,TS val 3802144636 ecr 0,nop,wscale 7], length 0
- 00:41:39.691836 IP 10.0.2.15.33720 > 130.211.189.113.443: Flags [.], ack 50376, win 29200, length 0
- 00:41:39.692121 IP 10.0.2.15.33720 > 130.211.189.113.443: Flags [P.], seq 0:198, ack 1, win 29200, length 198
- 00:41:39.769114 IP 10.0.2.15.33720 > 130.211.189.113.443: Flags [.], ack 1409, win 30976, length 0
- 00:41:39.769470 IP 10.0.2.15.33720 > 130.211.189.113.443: Flags [.], ack 2817, win 33792, length 0
- 00:41:39.769784 IP 10.0.2.15.33720 > 130.211.189.113.443: Flags [.], ack 3912, win 36608, length 0
- 00:41:39.773737 IP 10.0.2.15.33720 > 130.211.189.113.443: Flags [P.], seq 198:324, ack 3912, win 36608, length 126
- 00:41:39.833725 IP 10.0.2.15.33720 > 130.211.189.113.443: Flags [P.], seq 324:751, ack 3912, win 36608, length 427
- 00:41:39.902096 IP 10.0.2.15.33720 > 130.211.189.113.443: Flags [.], ack 3918, win 36608, length 0
- 00:41:39.902280 IP 10.0.2.15.33720 > 130.211.189.113.443: Flags [.], ack 3963, win 36608, length 0
- 00:41:39.934513 IP 10.0.2.15.33720 > 130.211.189.113.443: Flags [.], ack 4329, win 39424, length 0
.
.
.
.
.
72 packets captured
72 packets received by filter
0 packets dropped by kernel

*The security.codepath.com site has far fewer resources to load, with no explicit calls to javascript files or image files.*

*Challenge 2*

![](https://github.com/dallens/CodepathWeek9Honeypots/blob/master/w9_m2c2orange.png)

### Milestone 3
*Look at the source and destination IPs; how much of the traffic is inbound vs. outbound?*
Mostly outbound.
![](https://github.com/dallens/CodepathWeek9Honeypots/blob/master/w9_m3WindowsIsChatty.png)
*Try nslookup on a couple of IPs that aren't in your network. See if you can figure out who those IPs belong to*
![](https://github.com/dallens/CodepathWeek9Honeypots/blob/master/w9_m3nslookup.png)
*Try to identify traffic associated with at least one process on your host that's either part of the OS itself or is auto-launched at startup*
![](https://github.com/dallens/CodepathWeek9Honeypots/blob/master/w9_m3nbns.png)
*See if you can spot any ARP packets used to resolve IPs to MAC addresses*
![](https://github.com/dallens/CodepathWeek9Honeypots/blob/master/w9_m3arp.png)

### Milestone 4
![](https://github.com/dallens/CodepathWeek9Honeypots/blob/master/w9_m4wiresharksetup.png)
http://checkip.dyndns.org/ is used to identify the public IP of the affected machine.
The GET requests and domains are file downloads requested by the upatre malware that was in the email, each containing a portion of dyreza. Different domains allow for the splitting of the malicious file potentially avoiding detection by both an IDS and AV.
The initial upatre malware that downloaded dyreza was delivered via a .zip file as an email attachment.

### Milestone 5
![](https://github.com/dallens/CodepathWeek9Honeypots/blob/master/w9_m5exe.png)

### Milestone 6
![](https://github.com/dallens/CodepathWeek9Honeypots/blob/master/w9_m6aircrack.png)

### Milestone 7
Not undertaken due to rules regulating on campus wifi.

## Honeypot Report
![](https://github.com/dallens/CodepathWeek9Honeypots/blob/master/w9_scangif.gif)

1. Honeypot Deployed: Dionaea
1. Honeypot Deployed: Dionaea
  - [ ] Summary:
    - Number of Attacks: 1102
    - Number of Unique IPs:
    - cat session.json | awk -F "," '{print $5}' | sort | uniq -c |sort -r |wc -l == ```64```
-      1003  "source_ip" : "139.182.205.36"
-        20  "source_ip" : "111.73.46.39"
-         3  "source_ip" : "77.72.85.25"
-         3  "source_ip" : "182.184.123.11"
-         3  "source_ip" : "149.28.207.30"
-         3  "source_ip" : "146.185.241.2"
-         2  "source_ip" : "5.188.86.142"
-         2  "source_ip" : "45.77.80.118"
-         2  "source_ip" : "45.77.117.249"
-         2  "source_ip" : "45.32.132.179"
-         2  "source_ip" : "144.202.41.232"
-         2  "source_ip" : "144.202.38.165"
-         2  "source_ip" : "144.202.36.135"
-         2  "source_ip" : "140.82.24.240"
-         2  "source_ip" : "104.207.146.143"
-         1  "source_ip" : "94.52.179.51"
-         1  "source_ip" : "92.63.197.97"
-         1  "source_ip" : "89.68.130.0"
-         1  "source_ip" : "86.122.193.194"
-         1  "source_ip" : "77.72.85.117"
-         1  "source_ip" : "60.235.38.147"
-         1  "source_ip" : "5.188.9.29"
-         1  "source_ip" : "5.188.87.19"
-         1  "source_ip" : "45.77.112.204"
-         1  "source_ip" : "45.55.0.154"
-         1  "source_ip" : "37.79.114.204"
-         1  "source_ip" : "37.191.162.245"
-         1  "source_ip" : "216.244.77.186"
-         1  "source_ip" : "212.83.162.62"
-         1  "source_ip" : "205.205.150.33"
-         1  "source_ip" : "196.52.43.96"
-         1  "source_ip" : "196.52.43.58"
-         1  "source_ip" : "196.52.43.51"
-         1  "source_ip" : "196.52.43.126"
-         1  "source_ip" : "193.112.62.43"
-         1  "source_ip" : "192.241.234.205"
-         1  "source_ip" : "192.241.182.244"
-         1  "source_ip" : "190.6.23.98"
-         1  "source_ip" : "189.253.89.122"
-         1  "source_ip" : "188.18.157.180"
-         1  "source_ip" : "187.63.29.100"
-         1  "source_ip" : "185.246.130.7"
-         1  "source_ip" : "185.232.28.195"
-         1  "source_ip" : "185.222.210.46"
-         1  "source_ip" : "185.170.42.14"
-         1  "source_ip" : "182.31.33.34"
-         1  "source_ip" : "181.214.87.34"
-         1  "source_ip" : "181.214.87.30"
-         1  "source_ip" : "180.97.200.230"
-         1  "source_ip" : "180.97.106.164"
-         1  "source_ip" : "149.28.201.191"
-         1  "source_ip" : "144.202.47.92"
-         1  "source_ip" : "144.202.33.62"
-         1  "source_ip" : "133.123.64.130"
-         1  "source_ip" : "119.40.84.155"
-         1  "source_ip" : "118.187.4.147"
-         1  "source_ip" : "117.211.169.173"
-         1  "source_ip" : "117.161.3.59"
-         1  "source_ip" : "113.30.24.42"
-         1  "source_ip" : "112.133.222.150"
-         1  "source_ip" : "110.170.19.251"
-         1  "source_ip" : "107.170.226.201"
-         1  "source_ip" : "106.51.127.163"
-         1  "source_ip" : "104.131.41.8"
    - Malware Samples: None
    - Protocols:
    - cat session.json | awk -F "," '{print $2}' | sort | uniq -c | wc == ```7```
-        1055  "protocol" : "pcap"
-        25  "protocol" : "httpd"
-        11  "protocol" : "SipSession"
-         6  "protocol" : "smbd"
-         2  "protocol" : "mysqld"
-         2  "protocol" : "mssqld"
-         1  "protocol" : "ftpd"
  - [ ] json export: [json](https://github.com/dallens/CodepathWeek9Honeypots/blob/master/session.json)

# At Last Check...
![](https://github.com/dallens/CodepathWeek9Honeypots/blob/master/w9_adminconsole.png)
## Assets

Google Cloud License and Dionaea Honeypot


GIFs created with [LiceCap](http://www.cockos.com/licecap/).

## Notes
Severely limited funds for Google Cloud instances constrained acquisition of additional or long-term honeypot data.


## License

    Copyright 2018

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
