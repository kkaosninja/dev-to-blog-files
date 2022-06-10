https://tryhackme.com/room/superspamr

*Defeat the evil Super-Spam, and save the day!!*

----

###1)  Enumeration

```bash
# Nmap 7.91 scan initiated Sat Aug  7 19:25:30 2021 as: nmap -p- -A -Pn -oN resultsNmap -vv 10.10.110.84                                                                   
Nmap scan report for 10.10.110.84                                                                                                                                          
Host is up, received user-set (0.17s latency).                                                                                                                             
Scanned at 2021-08-07 19:25:31 IST for 360s                                                                                                                                
Not shown: 65530 closed ports                                                                                                                                              
Reason: 65530 resets                                                                                                                                                       
PORT     STATE SERVICE REASON         VERSION                                                                                                                              
80/tcp   open  http    syn-ack ttl 60 Apache httpd 2.4.29 ((Ubuntu))                                                                                                       
|_http-generator: concrete5 - 8.5.2                                                                                                                                        
| http-methods:                                                                                                                                                            
|_  Supported Methods: GET HEAD POST OPTIONS                                                                                                                               
|_http-server-header: Apache/2.4.29 (Ubuntu)                                                                                                                               
|_http-title: Home :: Super-Spam                                                                                                                                           
4012/tcp open  ssh     syn-ack ttl 60 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)                                                                         
| ssh-hostkey:                                                                                                                                                             
|   2048 86:60:04:c0:a5:36:46:67:f5:c7:24:0f:df:d0:03:14 (RSA)                                                                                                             
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCjPfdefRhbpiW/oi5uUVtVRW/pYZcnADODOU4e80iSnuqWfRB5DAXTpzKZNw5JBQGy+4Amwz0DyX/TlYBgXRxPXwFimpBXnc02jpMknSaDzdRnInU8wFcsBQc+GraYz1mMH
vRcco2FfIrKurDbyEsBCzwJuk/RKdSq2rcFLhq8QAPoxc9FQcNeUIZrBt53/7+fD7B7NvjjU22+hXZhjt6PLC3LDWcaMvpYCxMYGwKoC9xTs+FtzEFrt6yWzKrXV1iNuKdNyt8vu22bcPl2GrQ9ai9I89DEY4wB3dADP6AfNikb
i0QWjdNbW2fhblG9PvKRu9s3IbpVueX2qBfInuAF                                                                                                                                   
|   256 ce:d2:f6:ab:69:7f:aa:31:f5:49:70:e5:8f:62:b0:b7 (ECDSA)                                                                                                            
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIs/ZpOvCaKtCEwW4YraPciYLZnrRXDR6voHu0PipWaQpcdnsc8Vg1WMpkX0xgjXc9eD3NuZmBtTcIDTJXi7v4U=         
|   256 73:a0:a1:97:c4:33:fb:f4:4a:5c:77:f6:ac:95:76:ac (ED25519)                                                                                                          
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHHX1bbkvh6bRHE0hWipYWoYyh+Q+uy3E0yCBOoyY888                                                                                         
4019/tcp open  ftp     syn-ack ttl 60 vsftpd 3.0.3                                                                                                                         
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxr-xr-x    2 ftp      ftp          4096 Feb 20 14:42 IDS_logs
|_-rw-r--r--    1 ftp      ftp           526 Feb 20 13:53 note.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.17.9.26
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text 
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable 
|_End of status
5901/tcp open  vnc     syn-ack ttl 60 VNC (protocol 3.8)
| vnc-info: 
|   Protocol version: 3.8
|   Security types: 
|     VNC Authentication (2)
|     Tight (16)
|   Tight auth subtypes: 
|_    STDV VNCAUTH_ (2)
6001/tcp open  X11     syn-ack ttl 60 (access denied)
```

#####Observations from nmap scan.  
  
- Port 80 - Apache 2.4.29 - Webserver  
    Running a website that makes use of Concrete5 CMS 8.5.2 ( looking at page source, and also using Wappalyzer )  
    Possible XSS Exploit - [Concrete5 8.5.4 - 'name' Stored XSS](https://www.exploit-db.com/exploits/49721), https://raw.githubusercontent.com/Quadron-Research-Lab/CVE/main/CVE-2021-3111.pdf  
    Another possible RCE Exploit -> https://hackerone.com/reports/768322, https://github.com/concrete5/concrete5/issues/8319  
      
- Port 4012 - SSH - OpenSSH 7.6p1  
    
- Port 4019 - FTP - vsftpd 3.0.3  
    Anonymous login allowed. Let's take a look inside.
    
    ```bash
    ftp> ls -la
    227 Entering Passive Mode (10,10,140,162,190,141).
    150 Here comes the directory listing.
    drwxr-xr-x    4 ftp      ftp          4096 May 30 19:26 .
    drwxr-xr-x    4 ftp      ftp          4096 May 30 19:26 ..
    drwxr-xr-x    2 ftp      ftp          4096 May 30 19:26 .cap
    drwxr-xr-x    2 ftp      ftp          4096 Feb 20 14:42 IDS_logs
    -rw-r--r--    1 ftp      ftp           526 Feb 20 13:53 note.txt
    
    ftp> ls                                                                                           227 Entering Passive Mode (10,10,140,162,182,217).                                               150 Here comes the directory listing.                                                             -rwxr--r--    1 ftp      ftp        370488 Feb 20 14:46 SamsNetwork.cap                           226 Directory send OK.                                                                           ftp> ls -la                                                                                       227 Entering Passive Mode (10,10,140,162,193,19).                                                 150 Here comes the directory listing.
    drwxr-xr-x    2 ftp      ftp          4096 May 30 19:26 .                            
    drwxr-xr-x    4 ftp      ftp          4096 May 30 19:26 ..                           
    -rw-r--r--    1 ftp      ftp           249 Feb 20 13:36 .quicknote.txt               
    -rwxr--r--    1 ftp      ftp        370488 Feb 20 14:46 SamsNetwork.cap
    ```
    

    > **VERY IMPORTANT** \- Usually we don't look for hidden files in FTP servers, which in this case would have caused me to miss the `.cap` directory. I'll admit I did not see them in my first attempt at the machine. Came back to the machine, and execute `ls -a` in an act of desperation, which thankfuly turned out to be true.  
      
    Contents of `note.txt`
    
    ```
    ┌──(kali㉿kali)-[~/Documents/thm_superspam]
    └─$ cat note.txt        
    12th January: Note to self. Our IDS seems to be experiencing high volumes of unusual activity.
    We need to contact our security consultants as soon as possible. I fear something bad is going
    to happen. -adam
    
    13th January: We've included the wireshark files to log all of the unusual activity. It keeps
    occuring during midnight. I am not sure why.. This is very odd... -adam
    
    15th January: I could swear I created a new blog just yesterday. For some reason it is gone... -adam
    
    24th January: Of course it is... - super-spam :)
    
    ```  
    
    It seems we have to look into the `.pcap` files aka network capture files to get more info. Apparently whatever unusual stuff happened, it happened around midnight.  
      
    
    The hacker probably compromised the CMS and deleted the blog post left by this `adam` (possible username to keep in mind). And looks like the hacker is such a show-off that they left a message in `note.txt`.    
      
  
    After going into the `IDS_logs` folder, we see so many files. Most of the files in this dir are zero-byte files. But there were four .pcap files that I downloaded, which were the only ones that had any bytes in them.  

    ![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/83si7olkm7p7e8a5y144.png)  
  

    Now, to the contents of the `.cap` directory.
    Contents of `.quicknote.txt`
    
    ```
    └─$ cat .quicknote.txt                           
     It worked... My evil plan is going smoothly.
     I will place this .cap file here as a souvenir to remind me of how I got in...
     Soon! Very soon!
     My Evil plan of a linux-free galaxy will be complete.
     Long live Windows, the superior operating system!
    ```
    
    The other file in this directory is `SamsNetwork.cap`. So according to `super-spam`, this capture file contains the means for us to "get in", whatever that means.  
  
----  
  
###2) Foothold  
  
#### PHP File Upload Attempt

For this, my first attempt was to get a reverse shell using a PHP file upload.  

While going through the blog, I noticed that the blog posts allowed comments to be made, along with attachments. 

Although image attachments were allowed in the comments, PHP attachments were not. This was due to a client-side filter(jQuery file upload handling code). 
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/ir9r8p7ohnl4px95vypk.png)  

This filter can easily be avoided by modifying the page response using a proxy(Burp Intercept/ZAP Breakpoint).   

But even after this, there seemed to be server-side filters preventing a file upload.
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/pi2t3stxjgod7t3zx13h.png)
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/cztdla8vghoqbhqirl9p.png)  

----  
  
#### Cracking NTLM hashes found in "IDS_logs" packet captures

Now, let's take a step back and take a look at the packet captures. From `note.txt` earlier, the "unusual" activity was close to midnight.  
  
The 12th April 2021 pcap involves activity that occurs around 1 AM. Its mostly the SAMR protocol(https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380).   
  
The pcap files for 13th and 16th are regarding HTTP requests to a Chinese domain, which we will ignore for now.  
  
The pcap file for the 14th April 2021 is interesting, since it contains SMBv2 protocol captures that include NTLM authentication attempts. Let's see if we can get some useful data from this.  

> Note: Ultimately these credentials turned out to be useless, but it was a nice rabbit hole to follow :D  You can skip the NTLM hash cracking section and scroll down to the next one
  
Took the help of this article to crack the NTLM hash, because I'm a noob at this => https://research.801labs.org/cracking-an-ntlmv2-hash/  
  
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/3n5w18t2pz5vbjg7zsqc.png)

```
Domain Name: 3B
User Name: lgreen
Host name: 02694W-WIN10
    
NTProofStr: 73aeb418ae0e8a9ec167c4d0880cfe22
NTLMv2 Response:
    010100000000000049143c43a261d6012ce41adf31a1363c00000000020004003300420001001e003000310035003600360053002d00570049004e00310036002d004900520004001e0074006800720065006500620065006500730063006f002e0063006f006d0003003e003000310035003600360073002d00770069006e00310036002d00690072002e0074006800720065006500620065006500730063006f002e0063006f006d0005001e0074006800720065006500620065006500730063006f002e0063006f006d000700080049143c43a261d60106000400020000000800300030000000000000000100000000200000fc849ef6b042cb4e368a3cbbd2362b5ccc39324c75df3415b6166d7489ad1d2b0a001000000000000000000000000000000000000900220063006900660073002f003100370032002e00310036002e00360036002e0033003600000000000000000000000000
    
NTLM Server Challenge: a2cce5d65c5fc02f
```

According to the article, final crackme format is
    
```bash
username::domain:ServerChallenge:NTProofstring:modifiedntlmv2response
```  
    
which in our case would be
    
```bash
lgreen::3B:a2cce5d65c5fc02f:73aeb418ae0e8a9ec167c4d0880cfe22:010100000000000049143c43a261d6012ce41adf31a1363c00000000020004003300420001001e003000310035003600360053002d00570049004e00310036002d004900520004001e0074006800720065006500620065006500730063006f002e0063006f006d0003003e003000310035003600360073002d00770069006e00310036002d00690072002e0074006800720065006500620065006500730063006f002e0063006f006d0005001e0074006800720065006500620065006500730063006f002e0063006f006d000700080049143c43a261d60106000400020000000800300030000000000000000100000000200000fc849ef6b042cb4e368a3cbbd2362b5ccc39324c75df3415b6166d7489ad1d2b0a001000000000000000000000000000000000000900220063006900660073002f003100370032002e00310036002e00360036002e0033003600000000000000000000000000
```  
Saving above to a file called `crackme.txt` and running `hashcat` on my host machine, with `rockyou.txt` as a password list.  
  
```bash
❯ hashcat -m 5600 crackme.txt rockyou.txt 
    hashcat (v6.1.1) starting...
      
LGREEN::3B:a2cce5d65c5fc02f:73aeb418ae0e8a9ec167c4d0880cfe22:010100000000000049143c43a261d6012ce41adf31a1363c00000000020004003300420001001e003000310035003600360053002d00570049004e00310036002d004900520004001e0074006800720065006500620065006500730063006f002e0063006f006d0003003e003000310035003600360073002d00770069006e00310036002d00690072002e0074006800720065006500620065006500730063006f002e0063006f006d0005001e0074006800720065006500620065006500730063006f002e0063006f006d000700080049143c43a261d60106000400020000000800300030000000000000000100000000200000fc849ef6b042cb4e368a3cbbd2362b5ccc39324c75df3415b6166d7489ad1d2b0a001000000000000000000000000000000000000900220063006900660073002f003100370032002e00310036002e00360036002e0033003600000000000000000000000000:CENSORED
```  
SUCCESS!! Our password is `CENSORED`, for the user `lgreen`

- Trying this password for the VNC service at port 5901. Nope not working.  
- Let's try the `lgreen:CENSORED` combo for the SSH Service at port 4012. Nope not working.  
- Maybe trying at the login portal in Concrete5 CMS will work? Tried. Nope not working. Tried with `admin` and `root` usernames as well.  In case you are wondering where the "Login" portal can be found.
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/mfk7gcoq1dcuw0yat4fc.png)  
  
Ok, time to move on  

----  

#### Cracking WiFi password from SamNetwork.cap file  
  
Since we have gathered as much as possible(I think) from the IDS logs, let's see what we can infer from the SamsNetwork.cap packet capture, which apparently is how `super-spam` "got in".  
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/bwbljtcs493gwt1ox95w.png)  
  
Looks like a Network capture from a WiFi network. Looks like we'll have to use `aircrack-ng` to guess the password for the network. Let's use `rockyou.txt` as our wordlist.  

> Disclaimer: Not an expert on Wifi cracking :D Just used this command after reading some articles on how to crack Wifi passwords. 
  
 
`aircrack-ng -w /usr/share/wordlists/rockyou.txt SamsNetwork.cap`
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/gc2r3iiulq3c5pig6mvs.png)  
  
Password found is CENSORED. Let's try this in the login portal for the Blog. But what usernames do we use? Good question. Let's simply try using the usernames that are available in the blog posts themselves.

- Go to https://10.10.142.204/concrete5/index.php/blog
- Click on each of the Individual blog posts and extract the usernames found. We get a total of four users.  
  
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/c1uf1e94eon20c2jpa0u.png)

The usernames we find are:  
- adam_admin
- benjamin_blogger
- lucy_loser
- donald_dump

Let's try the password we just found for all of these usernames in the Blog Login portal.

Success! The password works for the user **donald_dump.**  
  
#### Uploading a PHP Reverse Shell.

When you log in, you will see what looks like a debugging stack trace. But the URL will be set to `http://IP/concrete5/index.php/dashboard/welcome`.  
  
Just change the URL to "http://IP/concrete5/index.php", and we will be at the home page in "dashboard" mode for the CMS.  

Now that we logged in to the CMS, let's try to upload a PHP reverse shell to get a foothold in the machine. Click on Settings(top-right corner button), go to File Manager. Here there is an "Upload Files" button. Let's try that.  

![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/ta1r7fxepsu9nczqwq2m.png)  

We get an Invalid File Extension(hover cursor over the uploaded file box).   
  
At this point, we must remember that we found an [RCE exploit for Concrete5 CMS 8.5.2](https://hackerone.com/reports/768322)(scroll up to the beginning of the Foothold section).

- https://hackerone.com/reports/768322
- https://github.com/concrete5/concrete5/issues/8319

According to the HackerOne report, we need to go to Settings -> "System & Settings" -> Allowed File Types(under Files), and add PHP. Apparently, this will allow us to configure the File Manager to allow PHP file uploads. The report also says we need an "Admin" role. Looking at the Donald\_Dump user in Dashboard -> Members -> Donald\_Dump we see  
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/9m6hpmcmx965bjz29s2u.png)  

With that taken care of, let's try to add PHP to the list of allowed extensions.  
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/4xv7vg6tvn0ghs2yd2sl.png)  

And now let's go back to File Manager and see if we can upload our reverse shell file.  
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/mltsci2h88i1dlw2uin7.png)  

It works! Note down the "URL to File". Since the CMS seems to be using random number folder names to store uploaded files, we will need the exact path to access this, to get our reverse shell.

The URL was like this for me => `http://10.10.140.162/concrete5/application/files/7516/2852/3656/revshell.php`

BTW this is the [Pentest Monkey PHP Reverse Shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) file.  

Start `netcat` listener, and then visit to the Reverse Shell URL in the browser.  

And we have shell! Foothold secured!  
  
----


#### Looking for user.txt  

Let's navigate around to look for the user flag in the home directory  
```bash
www-data@super-spam:/home$ ls -lR
.:
total 20
drwxr-xr-x 2 benjamin_blogger benjamin_blogger 4096 Apr  9 15:22 benjamin_blogger
drw-rw---- 6 donalddump       donalddump       4096 Apr  9 15:23 donalddump
drwxr-xr-x 7 lucy_loser       lucy_loser       4096 Apr  9 15:23 lucy_loser
drwxr-xr-x 5 root             root             4096 May 30 20:08 personal
drwxr-xr-x 4 super-spam       super-spam       4096 Apr  9 15:24 super-spam
    
./benjamin_blogger:
total 0
ls: cannot open directory './donalddump': Permission denied
    
./lucy_loser:
total 12
-rw-r--r-- 1 root root   28 Feb 24 17:27 calcs.txt
drwxr-xr-x 2 root root 4096 Feb 24 17:27 prices
drwxr-xr-x 2 root root 4096 Feb 24 17:27 work
    
./lucy_loser/prices:
total 0
    
./lucy_loser/work:
total 0
    
./personal:
total 12
drwxr-xr-x 2 root root 4096 May 30 20:07 Dates
drwxr-xr-x 2 root root 4096 May 30 20:07 Work
drwxr-xr-x 2 root root 4096 May 30 20:08 Workload
    
./personal/Dates:
total 0
    
./personal/Work:
total 4
-rw-r--r-- 1 root root 47 May 30 19:56 flag.txt
    
./personal/Workload:
total 4
-rw-r--r-- 1 root root 215 Feb 20 17:04 nextEvilPlan.txt
    
./super-spam:
total 4
-rw-r--r-- 1 root root 251 Feb 24 17:25 flagOfWindows
```
And we have found our flag.txt in `/home/personal/Work/flag.txt`  

Also, the names of all the users who have folders in the `/home/` folder
	
- benjamin_blogger
- donalddump
- lucy_loser
- super-spam

Let's have a look at the other folders and see if we can get something useful.  

Found something in `lucy_loser`'s directory
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/d7fkdd076nkh3yj70yz1.png)  

Well well. Looks like Lucy's a traitor :D And they are using **XOR** encryption to communicate. The folder also a file `xored.py` that allows you to XOR two images and output a result image.  
  
----  

#### Finding the answers for the "encryption" questions  

The folder has ten files of the type `cX.png`, where X ranges from 1-10. And then a `d.png`.
  
My guess is we can use the `xored.py` script to remove the overlay(which was added as part of encryption probably), to make the underlying text more clearer.
  
The encryption process is not intuitive, since we don't know what the "key" file is.

As for how XOR Encryption works, read the "Example" section of this Wikipedia page => https://en.wikipedia.org/wiki/XOR_cipher  
  
So, technically speaking. "Original Message" XOR "Encryption Key" => "Encrypted Message"

Also, "Encrypted Message" XOR "Encryption Key" => "Original Message"  

The machine has `Python3`. So starting a web-server to download all the files so that we can do the work on our own machine. I was able to start the server on port 8080 and download the files.  
  
Looking at the files on my own system.
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/rwdbgya2197cde8fkrlx.png)

`d.png` is the clearest image of all the four. It has some underlying text, over which some Lorem Ipsum text has been super-imposed, which I am guessing is the result of a XOR operation.  
  
The cX.png files are not legible. The d.png is as follows.
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/frr6ip33h2iqrjp7sqpc.png)  

I did not run the XOR Encryption. Just opened the file in an Image Viewer, and zoomed in as much as possible, and then typed out the message, which is  
```
Senior Favaeull, I am sending you this encrypted message so that you can maintain your persistence on the machine. Please be assured that I have encypted this message using Xor. I have told that clumsy assistant of mine to use different random keys for each message sent. I hope this finds you well. The new password will grant you access, it is the following: CENSORED. stay safe and well.
    
-Super Spam
```  

To be absolutely sure about the password(especially the first half), I tried running `xored.py` for the cX.png files against each other. I got a good result for c8.png XOR c4.png.  
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/p3nb28i29flu75asso4v.png)  
  
In the TryHackMe room, the password we obtain in this step is the answer for
> Q:  What key information was embedded in one of super-spam's encrypted messages?  

Now, who the hell is Favaeull? The "clumsy assistant" mentioned here is clearly Lucy.  
  
Tried this password all users on the SSH port 4012.   
Success! It works for *donalddump*. Now we have a proper shell.  

----

###3) Privilege Escalation

We can finally look into the `/home/donalddump/` dir. We cannot change into the home dir initially. This is due to lack of execute permissions. Just execute `chmod u+x donalddump` and get in.  
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/vnmmpnfky57wukk9j0hc.png)  

Now there is a strange `passwd` file here. It has some bytes. Try reading it in vim, and this is what you see.
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/cw5k6l2hhumxxv2hqp4h.png)  

Now I did not know what to make of this. Probably encoding/encryption of some kind.  
  
I kept this aside, and ran the [linPEAS.sh](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) script to find PrivEsc vectors.  

That's when I came across this strange entry in the process list in the linPEAS results
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/2bdsf3peifr2o4nscbnl.png)  

You might wonder why this caught my eye. If you scroll up to the beginning, and look at the `nmap` enumeration, you will see we have a VNC service running at port 5901, which we haven't used for anything yet.  
  

Also another entry that caught my eye, that will be useful later on.
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/sucqvztb3iapkl3nt141.png)  

Those lines are from the machine's `/etc/ssh/sshd_config` file => https://github.com/carlospolop/PEASS-ng/blob/master/linPEAS/linpeas.sh#L2314  
  
So `root` login via SSH is allowed. Good thing to keep in mind.  

----  

#### Finding a way to connect to the VNC service  
  
So now, I am guessing this is a password file for the VNC service. Let's try to find some details.  
  
So Startpage search for "vnc passwd file" => https://www.tightvnc.com/vncpasswd.1.php  

So I am thinking, since we can't get the original password, why not try to change the password. The `vncpasswd` command is available on the machine. But when we try to run it, it asks for a password.
```bash
donalddump@super-spam:~$ vncpasswd 
Using password file /home/donalddump/.vnc/passwd
VNC directory /home/donalddump/.vnc does not exist, creating.
Password: 
Password too short
```  
  
Since this is my first time dealing with TightVNC, I assume maybe I can try to set a new password. So I do a search for "change vnc password", and I come across this article => https://linuxconfig.org/how-to-change-vnc-password-on-linux  

After reading this article, it dawns on me that this is an encrypted password, which is the output of the `vncpasswd` command. Ok. Now search for "decrypt vnc password".

And I find https://github.com/jeroennijhof/vncpwd. A very convenient utility to help you decrypt the password.  
  
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/vxvr18azo89lrxoiiqeg.png)  

And we have the VNC Service password! Let's try connecting to it.  
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/btnfrvpjxrwaig2z6rcc.png)
  

Aaaand we have root shell! But there is no root flag in the home dir.  
  
----  
  
#### Finding the root.txt file  

This VNC session is very inconvenient to navigate around. If you remember from earlier, this machine allows root login via SSH. So let's generate some SSH keys to enable private key login. 

Run below commands on remote machine  
- `ssh-keygen` to generate keys
- `cd /root/.ssh/ && cat id_rsa.pub > authorized_keys`
- Run Python3 webserver and download private key file `id_rsa` onto your machine  
  
On your local machine(assuming Kali)  
- `sudo chown kali:kali id_rsa`
- `sudo chmod 600 id_rsa`  
  
Now use this key file to login to the machine using the SSH Service at port 4012.

![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/4gbh6sc72m1jhmtkuhnk.png)

Executing an `ls -laR` in the `root` home dir yields the following.  
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/sm3tfqb5u3h2sh1i8bts.png)  

So the root flag is in `/root/.nothing/r00t.txt`. Note the zeroes in the file name.  
  
The contents are as follows:  
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/4acvrl2j9mz1kejvpwn9.png)  

We will have to decode it to get the answer. This was obviously not Base64. I initially tried https://rot13.com/ but that did not yield anything.  

This is where @tan on the THM Discord server gave me a hint about trying to use [GCHQ CyberChef](https://gchq.github.io/CyberChef/) magic formula to try and guess what kind of encoding this was.  

![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/nt4jufzhovgl2r5csm6s.png)

Aaand done!! Whew what a ride that was. Thanks for reading!  

Seriously recommend trying the machine yourself => https://tryhackme.com/room/superspamr
