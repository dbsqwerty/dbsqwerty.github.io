---
layout: post
title:  "Whitehacks 2021 "
date:   2021-03-08
categories: writeups
---

## Intro

I played this CTF with [Ariana](https://ariana1729.github.io/) and [River](http://dihydrogen.monoxide.tech/) as team Cat Cracking Crypto Problem and we got first. Wheeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee



## OSINT (Brief Explanations)

**Birthday Surprise A - Age Unknown:** 

`So, it's my friend's birthday soon and I want to surprise him. His name is Andrew Yeoh Boon How and I heard he's quite active on Twitter. Can you help me find out when is his birthday?`

* With a bit of google and persuasion, we uncover the following details

* ```
  username: andrewybh1997
  found accounts: twitter, tiktok, pastebin, instagram
  ```

* Going to the twitter account, we find out that his birthday is on September 18

* Combine this with his username (1997) to get his birthday. 

`Flag: WH2021{18091997}`



**Birthday Surprise B - The Cake Still Tick-Tocking:** 

`Now that we found out when is his birthday, we need to find out his favourite cake! He might have other social media. Not really sure though, he never mentioned it to me. The only thing I know is that he said he often vlogged somewhere.`

* He vlogs, and he has tiktok. So this means the video is on Tiktok
* Now the next step is something i severely regret doing and till this day still gives me PTSD. Tiktok is not for everyone, consult a doctor to find out if its suitable for you. In my case, it really is not suitable. Im still suffering the trauma and stress from this Tiktok browsing experience. Pls send help to me. (DO NOT TRY THIS AT HOME KIDS) Please kids, TikTok is horrible and is not meant. Stop getting infected by the TikTok virus. Uncle Roger "HAIYAAAAAAAAAAAAAAAAAAAAA" at all the tiktok users. 
* Anyways......... (eye cancer warning)
* ![](https://imgur.com/a/rm8tVYK)

`Flag: WH2021{Ch0c0_L4V4_1s_b3$t}` (again, im still traumatised by this tiktok experience. send help pls)



**Birthday Surprise C - No Place Like Home:** `Great! Now this might sounds bad, but I have no clue where he lives. Can you help me find out where?`

* Things we can gather from his Instagram posts. 

  * His House is a few MRT stops away from Gardens by the bay. (This leads us to suspect either Downtown Line MRT stations from Bayfront to Jalan Besar)
  * Second Post is taken from Sim Lin Square (Google Street View confirms this)
  * His house has a Bak Kwa Store and a bakery below
  * He took a picture at Fu Lu Shou Complex (which must be relatively near to his house)

* As such, with this info, let us draw some circles around these places.

* The circle overlap around The Bencoolen. The Bencoolen also has a Bak Kwa Store, a Bakery, and houses

* As such our final location is The Bencoolen

  ![](https://imgur.com/a/XJOX8hI)

`Flag: WH2021{189646}`



## Forensics (Is It Really)

 `A malicious file was downloaded and picked up by our antivirus...`

* This Challenge is simply a file carving exercise.

* What is file carving? Pls go google it up. thank you so much

  ```
   /CTF  binwalk signup.pdf                                                                    ✔ │ vagrant@ubuntu-bionic
  
  DECIMAL       HEXADECIMAL     DESCRIPTION
  --------------------------------------------------------------------------------
  0             0x0             PDF document, version: "1.3"
  69            0x45            Zip archive data, at least v2.0 to extract, uncompressed size: 332, name: __MACOSX/._eicar.txt
  530           0x212           End of Zip archive, footer length: 22
  443311        0x6C3AF         End of Zip archive, footer length: 22
  ```

`Flag: WH2021{eicar.txt}`



## Forensics (Can you handle these files?)

`Download the memory image from one of the sources.
An attacker is in our system and has left a note behind. Can you find the link in his note that leads us to the flag? `

* This is a very standard Memory Forensics Challenge

* For those who are new to memory forensics, the tool of choice is Volatility 2.6 to analyse the memory dump. Additionally, you would have run `imageinfo` to determine the profile of this memory dump, which in this case is `Win7SP1x64`

* First we triage the memory dump by running a few standard commands to understand what is going on. 

  * Process Scan

    ```
    sean@ubuntu:~/Desktop/volatility$ ./vol.py -f ../../memdump.mem --profile=Win7SP1x64 pstree
    Volatility Foundation Volatility Framework 2.6.1
    Name                                                  Pid   PPid   Thds   Hnds Time
    -------------------------------------------------- ------ ------ ------ ------ ----
     0xfffffa80039f0060:wininit.exe                       420    348      3     78 2021-02-20 13:20:56 UTC+0000
    	
    	... ... 
    	
     0xfffffa8005506810:explorer.exe                     2332   2288     30    912 2021-02-20 13:21:03 UTC+0000
    . 0xfffffa8002990920:notepad.exe                     3800   2332      1     61 2021-02-20 14:17:11 UTC+0000
    . 0xfffffa8005315060:chrome.exe                      1692   2332     31    860 2021-02-20 14:17:19 UTC+0000
    .. 0xfffffa800291e630:chrome.exe                     3404   1692     13    203 2021-02-20 14:17:23 UTC+0000
    .. 0xfffffa8005942b30:chrome.exe                     3424   1692     13    204 2021-02-20 14:17:40 UTC+0000
    .. 0xfffffa800267a820:chrome.exe                     2592   1692      7    132 2021-02-20 14:17:19 UTC+0000
    .. 0xfffffa8002b409e0:chrome.exe                     1224   1692     19    248 2021-02-20 14:17:48 UTC+0000
    .. 0xfffffa8004335930:chrome.exe                     3212   1692      9    233 2021-02-20 14:17:19 UTC+0000
    .. 0xfffffa8002a6a720:chrome.exe                     2404   1692     14    216 2021-02-20 14:17:19 UTC+0000
    .. 0xfffffa8002b262a0:chrome.exe                     2664   1692      8     89 2021-02-20 14:17:19 UTC+0000
    . 0xfffffa80039481a0:notepad.exe                     3380   2332      1     61 2021-02-20 14:17:12 UTC+0000
    . 0xfffffa80026b27d0:FTK Imager.exe                  3440   2332     16    325 2021-02-20 14:29:31 UTC+0000
    . 0xfffffa800426c6a0:notepad.exe                     3352   2332      1     61 2021-02-20 14:16:43 UTC+0000
    . 0xfffffa80057beb30:vmtoolsd.exe                    2496   2332      7    249 2021-02-20 13:21:04 UTC+0000
    .. 0xfffffa80026d2150:VMToolsHookPro                 2900   2496      1     30 2021-02-20 14:05:17 UTC+0000
    . 0xfffffa8002627640:notepad.exe                     3164   2332      1     61 2021-02-20 14:17:10 UTC+0000
    ```

  * Command History

    ```
    sean@ubuntu:~/Desktop/volatility$ ./vol.py -f ../../memdump.mem --profile=Win7SP1x64 cmdline
    Volatility Foundation Volatility Framework 2.6.1
    
    ... ...
    
    ************************************************************************
    notepad.exe pid:   3352
    Command line : "C:\Windows\system32\NOTEPAD.EXE" C:\Users\whitehacks\Desktop\400top.txt
    ************************************************************************
    notepad.exe pid:   3164
    Command line : "C:\Windows\system32\NOTEPAD.EXE" C:\Users\whitehacks\Desktop\flag.txt.txt
    ************************************************************************
    notepad.exe pid:   3800
    Command line : "C:\Windows\system32\NOTEPAD.EXE" C:\Users\whitehacks\Desktop\flag2.txt.txt
    ************************************************************************
    notepad.exe pid:   3380
    Command line : "C:\Windows\system32\NOTEPAD.EXE" C:\Users\whitehacks\Desktop\Untitled.txt
    ************************************************************************
    chrome.exe pid:   1692
    Command line : "C:\Program Files\Google\Chrome\Application\chrome.exe" 
    ************************************************************************
    chrome.exe pid:   2664
    Command line : 
    ************************************************************************
    ```

Lets take a step back and look at what we have so far. We know that there were many chrome tabs open as well as an interesting notepad process. It is usually common in CTF challenges for one to deal with chrome processes or notepad processes. Additionally, the command line history shows us that the challenge author created several text files which supposedly are the flag. The flag text files are also incredibly likely to contain the flag. 

* Lets try to find out what's inside the flag text files

* ```
  sean@ubuntu:~/Desktop/volatility$ ./vol.py -f ../../memdump.mem --profile=Win7SP1x64 mftparser | grep -A 10 -B 10 flag
  Volatility Foundation Volatility Framework 2.6.1
  
  
  $STANDARD_INFORMATION
  Creation                       Modified                       MFT Altered                    Access Date                    Type
  ------------------------------ ------------------------------ ------------------------------ ------------------------------ ----
  2021-02-20 14:14:39 UTC+0000 2021-02-20 14:15:11 UTC+0000   2021-02-20 14:15:11 UTC+0000   2021-02-20 14:14:39 UTC+0000   Archive
  
  $FILE_NAME
  Creation                       Modified                       MFT Altered                    Access Date                    Name/Path
  ------------------------------ ------------------------------ ------------------------------ ------------------------------ ---------
  2021-02-20 14:14:39 UTC+0000 2021-02-20 14:14:39 UTC+0000   2021-02-20 14:14:39 UTC+0000   2021-02-20 14:14:39 UTC+0000   Users\WHITEH~1\Desktop\flag.txt.txt
  
  $FILE_NAME
  Creation                       Modified                       MFT Altered                    Access Date                    Name/Path
  ------------------------------ ------------------------------ ------------------------------ ------------------------------ ---------
  2021-02-20 14:14:39 UTC+0000 2021-02-20 14:14:39 UTC+0000   2021-02-20 14:14:39 UTC+0000   2021-02-20 14:14:39 UTC+0000   Users\WHITEH~1\Desktop\FLAGTX~1.TXT
  
  ...
  
  
  $FILE_NAME
  Creation                       Modified                       MFT Altered                    Access Date                    Name/Path
  ------------------------------ ------------------------------ ------------------------------ ------------------------------ ---------
  2021-02-20 14:14:39 UTC+0000 2021-02-20 14:14:55 UTC+0000   2021-02-20 14:14:55 UTC+0000   2021-02-20 14:14:55 UTC+0000   Users\whitehacks\Desktop\flag2.txt.txt
  
  $OBJECT_ID
  Object ID: dca6fa73-7e73-eb11-b13c-147dda1578f4
  Birth Volume ID: 80000000-3000-0000-0000-180000000100
  Birth Object ID: 18000000-1800-0000-6d61-79626520796f
  Birth Domain ID: 75206172-6520-636c-6f73-650d0a2e2e2e
  
  $DATA
  0000000000: 6d 61 79 62 65 20 79 6f 75 20 61 72 65 20 63 6c   maybe.you.are.cl
  0000000010: 6f 73 65 0d 0a 2e 2e 2e                           ose.....
  sean@ubuntu:~/Desktop/volatility$ ^C
  
  ```

* As can be seen, flag2.txt tells us that we are close, which means that notepad is the way to go to solve this challenge. As such, let us dump Notepad's process and find any interesting strings inside which may give us the flag

* `/vol.py -f ../../memdump.mem --profile=Win7SP1x64 memdump -p 3352 --dump-dir=.`
  `strings 3352.dmp | grep -A 10 -B 10 flag.txt`

* ```
  sean@ubuntu:~/Desktop/volatility$ strings 3352.dmp | grep -A 10 -B 10 flag.txt
  hackunit.txt
  dead1.lnk
  wordmacro.txt
  acronyms.lnk
  acronyms.lnk
  cars.lnk
  ... ...
  https://imgur.com/a/pRWCNyo
  I see you have found me............
  FILE0
  
  ```

* Clicking on the link gives us the flag

* ![](https://imgur.com/a/pRWCNyo)

`Flag: WH2021{iSEEuHANDLEDthisWELL}`



## CSA (Sweet Tooth & Bad Code Practices)

**Sweet Tooth:**

`Help! There's an attacker who wants to use CSA's [website](https://csa.gov.sg/) for phishing! He had to copy CSA's web codes somewhere! Find out who is the attacker. P.S. We heard rumours that the attacker have some liking for Singaporean desserts`

* Generally, people store code in either github or gitlab. 
* So with a bit of effort and searching on github, we arrive at the supposed attacker. (Use github code search and search for Cyber Security Agency Singapore with the sorting based on last indexed)
* https://github.com/chachabooboo/csawebsite
* Go to his profile and wheee we get a flag

`Flag: WH2021{051N4_15_LOV3}`



**Bad Code Practices:**

`Looking at the codes, it seems that the attacker made multiple commits to hide a secret key.`

* So it seems that the flag must be hidden somewhere in the commits. After some searching, we gathered the following list of words that were changed. 

* ```
  j0!n
  A
  N
  ch@113ng1ng<space>
  eggc1t!ng
  f0r
  <script type="text/flag" rmb="{_}" src="WH2021 9_2_8_5_4_6_3_1_7"></script>
  <space>C5@
  fun<space>
  car33r
  ```

* After some flag guessing by my teammates, we get the final flag

`Flag: WH2021{j0!n_C5@_f0r_A_fun_ch@113ng1ng_N_eggc1t!ng_car33r}`



## Sponsor Flags

This is arguably the hardest challenge of the entire Whitehacks competition. Being an introvert with a fear of public speaking and social interaction, this challenge/challenges really pushed me to my limits. To get the flag, one supposedly merely has to talk with sponsors and do some trivial task such as filling up forms etc to obtain a flag. Yet due to my fear of public speaking, it took me lots of courage to even join the voice channel. After much "ughhs" and awkward silence, I somehow managed to extract the flags out of the sponsors, allowing my team to gain an ~~unfair~~ 1200 points bonus. 

## Remarks

Big Thanks to the organisers/challenge setters for making a fun and enjoyable CTF with 0 guessing needed which is amazing since there are **so many guessy CTF out there**

