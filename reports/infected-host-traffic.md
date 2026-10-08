# Historical lab report

> Archival coursework, not a fresh experiment. Team context is retained; individual responsibility is not inferred. Screenshots and raw captures are not bundled. Source evidence placeholders remain incomplete. Read [review notes](../docs/report-review-notes.md).

# COMP4337/9337 Lab 5 Report

## Security Analysis Using TShark / Wireshark

**Group Name:**  T16A-05
**Member Names and zIDs:**  

---

# Part A: Analysis of Infected Host Traffic

## Q1. Analyse Packet 14: Domain Name and Corresponding IP Address

By examining Packet 14 with `tshark`, the DNS query domain can be identified. By then checking the response in Packet 15, the resolved IP address for that domain can be determined.

```
14   1.145624  192.168.1.1 → 192.168.1.254 DNS 81 Standard query 0xa17e A w0rld.secilmisler.com 
15   1.539953  192.168.1.254 → 192.168.1.1 DNS 177 Standard query response 0xa17e A w0rld.secilmisler.com A 84.244.1.30 NS ns2.tr-shell.net NS ns1.tr-shell.net A 89.149.196.215 A 89.149.196.216
```

**Answer:**  

- Queried domain name: **w0rld.secilmisler.com**  
- Corresponding IP address: **84.244.1.30**  

---

## Q2. Perform a WHOIS Lookup on the IP Address in Packet 15

A WHOIS lookup was performed on the IP address shown in Packet 15 to identify the associated city information.

Historical WHOIS directory response omitted, including private contact details.

**Answer:**  

- IP address: `84.244.1.30`  
  - Associated city: `Irkutsk (historical registry contact location)`  

---

## Q3. Analyse Packet 16: Destination Port Connected by the Local Host

Inspect Packet 16 to determine the destination port number that the local host is attempting to connect to.

```
16   1.705462  192.168.1.1 → 84.244.1.30  TCP 62 1101 → 5050 [SYN] Seq=0 Win=65535 Len=0 MSS=1460 SACK_PERM
```

**Answer:**  
- Destination port: **5050**

---

## Q4. Identify the Bot Based on the Port and Analyse the TCP Stream

After looking up at www.speedguide.net, I found this by filtering port 5050,

| 5050 | tcp  | trojans | Yahoo Messenger uses this port.  BT Communicator uses ports 5050-5070 (TCP/UDP).  EOSCoreScada.exe in C3-ilex EOScada before 11.0.19.2 allows remote attackers to cause a denial of service (daemon restart) by sending data to TCP port (1) 5050 or (2) 24004. References: [[CVE-2012-1810](https://www.cve.org/CVERecord?id=CVE-2012-1810)]  R0xr4t [Symantec-2002-082915-1621-99], a.k.a. RoxRat backdoor, BD R0xr4t 1.0. Uses ports 5050,50551,50552,60551,60552. | *SG* |
| ---- | ---- | ------- | ------------------------------------------------------------ | ---- |
|      |      |         |                                                              |      |

So it means some of trojans used to use this port. But when I looked into the packet details, they didn’t match.

Using the destination port from Packet 16, perform an Internet search to determine which bots or malware are known to use this port. Then follow the corresponding TCP stream and analyse whom the bot is communicating with.

```
Follow: tcp,ascii
Filter: ((ip.src eq 192.168.1.1 and tcp.srcport eq 1101) and (ip.dst eq 84.244.1.30 and tcp.dstport eq 5050)) or ((ip.src eq 84.244.1.30 and tcp.srcport eq 5050) and (ip.dst eq 192.168.1.1 and tcp.dstport eq 1101))
Node 0: 192.168.1.1:1101
Node 1: 84.244.1.30:5050
22
NICK [P00|GBR|64180]

27
USER XP-2015 * 0 :ZOMBIE1

        1284
:CandC.local 001 [P00|GBR|64180] :Welcome to the CandC server [P00|GBR|64180]!XP-2015@192.168.1.1
:CandC.local 002 [P00|GBR|64180] :Your host is CandC.local
:CandC.local 003 [P00|GBR|64180] :This server was created May 6, 2006
:CandC.local 004 [P00|GBR|64180] CandC.local CandC script
:CandC.local 005 [P00|GBR|64180] CMDS=KNOCK,MAP,DCCALLOW,USERIP SAFELIST HCN MAXCHANNELS=10 CHANLIMIT=#:10 MAXLIST=b:60,e:60,I:60 NICKLEN=30 CHANNELLEN=32 TOPICLEN=307 KICKLEN=307 AWAYLEN=307 MAXTARGETS=20 WALLCHOPS :are supported by this server
:CandC.local 005 [P00|GBR|64180] WATCH=128 SILENCE=15 MODES=12 CHANTYPES=# PREFIX=(qaohv)~&@%+ CHANMODES=beI,kfL,lj,psmntirRcOAQKVGCuzNSMTG NETWORK=home CASEMAPPING=ascii EXTBAN=~,cqnr ELIST=MNUCT STATUSMSG=~&@%+ EXCEPTS INVEX :are supported by this server
:CandC.local 251 [P00|GBR|64180] :There are 1 users and 2 invisible on 1 servers
:CandC.local 252 [P00|GBR|64180] 1 :operator(s) online
:CandC.local 254 [P00|GBR|64180] 1 :channels formed
:CandC.local 255 [P00|GBR|64180] :I have 2 clients and 0 servers
:CandC.local 265 [P00|GBR|64180] :Current Local Users: 2  Max: 2
:CandC.local 266 [P00|GBR|64180] :Current Global Users: 2  Max: 2
:CandC.local 422 [P00|GBR|64180] :MOTD File is missing
:[P00|GBR|64180] MODE [P00|GBR|64180] :+iw

25
MODE [P00|GBR|64180] +B

16
JOIN #reptile 

        308
:[P00|GBR|64180]!XP-2015@192.168.1.1 JOIN :#reptile
:CandC.local 332 [P00|GBR|64180] #reptile :.version 
:CandC.local 333 [P00|GBR|64180] #reptile commander 1160011515
:CandC.local 353 [P00|GBR|64180] = #reptile :[P00|GBR|64180] @commander
:CandC.local 366 [P00|GBR|64180] #reptile :End of /NAMES list.

25
MODE [P00|GBR|64180] +B

        69
:commander!commander@admin.local PRIVMSG [P00|GBR|64180] :.VERSION.

16
JOIN #reptile 

25
MODE [P00|GBR|64180] +B

16
JOIN #reptile 

41
PRIVMSG #reptile :MAIN// Reptile (0.37)

        55
:commander!commander@admin.local TOPIC #reptile :.id 

58
NOTICE commander :.VERSION mIRC v6.14 Khaled Mardam-Bey.

        54
:commander!commander@admin.local TOPIC #reptile :.v 

83
PRIVMSG #reptile# :.WARN.// Version request from: commander!commander@admin.local

41
PRIVMSG #reptile :MAIN// Reptile (0.37)
```

**Answer:**  

- Bot / malware associated with this port: **CandC.local 001 [P00|GBR|64180] :Welcome to the CandC server [P00|GBR|64180]!XP-2015@192.168.1.1**

So basically the host was communicating with a CandC server and got infected, joint the `#reptile` channel, and interacted with an operator named `commander`.  After that this host may be used by the attacker to do something bad like launch a DDoS attack.

---

## Q5. Analyse Packet 95: DNS Query Domain Name

Inspect Packet 95 and record the DNS query domain name shown in that packet.

```
95   3.157968  192.168.1.1 → 192.168.1.254 DNS 75 Standard query 0xf079 A www.kinchan.net
```

**Answer:**  
- Domain name: **www.kinchan.net**

---

## Q6. Analyse Packet 111: TCP Stream and Local CGI Script Name

Inspect Packet 111 and follow the related TCP stream to determine the name of the local CGI script.

```
111   3.714568  192.168.1.1 → 202.189.151.5 HTTP 130 GET /cgi-bin/proxy.cgi HTTP/1.0 
tshark -r part-A-trace.pcap -T fields -e tcp.srcport -e tcp.dstport -Y frame.number==111
1109    80
```

```
└─$ tshark -r part-A-trace.pcap \
-q \
-z "follow,tcp,ascii,192.168.1.1:1109,202.189.151.5:80"

Follow: tcp,ascii
Filter: ((ip.src eq 192.168.1.1 and tcp.srcport eq 1109) and (ip.dst eq 202.189.151.5 and tcp.dstport eq 80)) or ((ip.src eq 202.189.151.5 and tcp.srcport eq 80) and (ip.dst eq 192.168.1.1 and tcp.dstport eq 1109))
Node 0: 192.168.1.1:1109
Node 1: 202.189.151.5:80
76
GET /cgi-bin/proxy.cgi HTTP/1.0
Host: www.kinchan.net
Pragma: no-cache

        1399
HTTP/1.1 404 Not Found
Date: Thu, 05 Oct 2006 01:25:17 GMT
Server: Apache/2.0.52 (Red Hat)
Vary: accept-language,accept-charset
Accept-Ranges: bytes
Connection: close
Content-Type: text/html; charset=iso-8859-1
Content-Language: en
Expires: Thu, 05 Oct 2006 01:25:17 GMT

<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head>
<title>Object not found!</title>
<link rev="made" href="mailto:webmaster@hut7.org" />
<style type="text/css"><!--/*--><![CDATA[/*><!--*/ 
    body { color: #000000; background-color: #FFFFFF; }
    a:link { color: #0000CC; }
    p, address {margin-left: 3em;}
    span {font-size: smaller;}
/*]]>*/--></style>
</head>

<body>
<h1>Object not found!</h1>
<p>

    The requested URL was not found on this server.

  

    If you entered the URL manually please check your
    spelling and try again.

  

</p>
<p>
If you think this is a server error, please contact
the <a href="mailto:webmaster@hut7.org">webmaster</a>.

</p>

<h2>Error 404</h2>
<address>
  <a href="/">security.ecs.soton.ac.uk</a><br />
  <span>Apache/2.0.40 (Red Hat Linux) mod_perl/1.99_07-dev Perl/v5.8.0 PHP/4.2.2 mod_python/3.0.1 Python/2.2.2 mod_ssl/2.0.40 OpenSSL/0.9.7a DAV/2</span>
</address>
</body>
</html>
```

**Answer:**  

- Local CGI script name: **proxy.cgi**

First, the TCP source and destination ports were identified from Packet 111. Then the TCP stream was followed to inspect the HTTP request, which shows that the requested CGI script was `/cgi-bin/proxy.cgi`. Although the request returned `404 Not Found`, the script name can still be identified from the request path.

---

## Q7. Malicious URL Checking Websites and Background Information on W32/Spybot

Common websites include:
- VirusTotal
- URLVoid
- Google Safe Browsing Transparency Report
- Cisco Talos Intelligence
- AbuseIPDB

According to the question prompt, the domain in this PCAP file was previously associated with W32/Spybot. **W32/Spybot is a bot malware family, often associated with IRC-based command-and-control activity.** Different variants may be capable of downloading additional malware, participating in DDoS attacks, stealing information, executing remote commands, and maintaining backdoor access to infected systems.

Other common malware types that users may encounter include:
- **Trojan**: Disguises itself as legitimate software to trick users into running it.
- **Ransomware**: Encrypts files and demands payment for recovery.
- **Spyware**: Secretly collects user information.
- **Worm**: Self-propagates across systems or networks.
- **Keylogger**: Records keystrokes to steal credentials.
- **Adware**: Displays unwanted advertisements and may track user activity.

---

## Q8. How to Prevent or Mitigate This Type of Threat

As a security administrator, several practical controls can be used to prevent or reduce the impact of this type of malicious traffic.

First, a firewall should be configured to restrict unnecessary inbound and outbound connections. This can help block suspicious traffic, prevent infected hosts from contacting external command-and-control servers, and reduce the attack surface of internal systems.

Second, whitelisting can be used to allow only approved applications, domains, or network connections. This makes it harder for unknown malware to run or communicate freely, because only trusted software and approved destinations are permitted.

Third, intrusion detection and intrusion prevention mechanisms should be deployed. An Intrusion Detection System (IDS) can monitor network traffic and raise alerts when suspicious behaviour is detected, while an Intrusion Prevention System (IPS) can go further by automatically blocking or interrupting malicious traffic. Tools such as Snort or Suricata are commonly used for this purpose.

In addition, packet analysis tools such as TShark and Wireshark can assist administrators in investigating unusual DNS requests, abnormal outbound connections, and possible command-and-control activity. This helps identify infected hosts and better understand the behaviour of the malware.

Overall, combining firewall rules, whitelisting, and IDS/IPS provides a stronger defence against botnet-related threats and other forms of malicious network activity.

