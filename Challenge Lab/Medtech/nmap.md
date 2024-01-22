## command
```
sudo nmap -Pn -A -T4 -oN nmap 192.168.234.120-122
```

## result

Nmap scan report for 192.168.234.120
```
Host is up (0.23s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 84:72:7e:4c:bb:ff:86:ae:b0:03:00:79:a1:c5:af:34 (RSA)
|   256 f1:31:e5:75:31:36:a2:59:f3:12:1b:58:b4:bb:dc:0f (ECDSA)
|_  256 5a:05:9c:fc:2f:7b:7e:0b:81:a6:20:48:5a:1d:82:7e (ED25519)
80/tcp open  http    WEBrick httpd 1.6.1 (Ruby 2.7.4 (2021-07-07))
|_http-server-header: WEBrick/1.6.1 (Ruby/2.7.4/2021-07-07)
|_http-title: PAW! (PWK Awesome Website)
Aggressive OS guesses: Linux 2.6.32 (88%), Linux 2.6.32 or 3.10 (88%), Linux 2.6.39 (88%), Linux 3.10 - 3.12 (88%), Linux 4.4 (88%), Synology DiskStation Manager 5.1 (88%), WatchGuard Fireware 11.8 (88%), Linux 2.6.35 (87%), Linux 4.9 (87%), Linux 3.4 (87%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 143/tcp)
HOP RTT       ADDRESS
1   236.87 ms 192.168.45.1
2   235.90 ms 192.168.45.254
3   236.43 ms 192.168.251.1
4   236.31 ms 192.168.234.120
```

Nmap scan report for 192.168.234.121
```
Host is up (0.23s latency).
Not shown: 996 closed tcp ports (reset)
PORT    STATE SERVICE       VERSION
80/tcp  open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: MedTech
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|11|2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows 11 21H2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2024-01-07T10:20:26
|_  start_date: N/A

TRACEROUTE (using port 143/tcp)
HOP RTT       ADDRESS
-   Hops 1-3 are the same as for 192.168.234.120
4   236.36 ms 192.168.234.121
```


Nmap scan report for 192.168.234.122
```

```


```
