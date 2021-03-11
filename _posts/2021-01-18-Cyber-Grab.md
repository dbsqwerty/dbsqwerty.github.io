---
layout: post
title:  "Cyber Grab CTF 2"
date:   2021-01-18
categories: writeups
---


Members:

[residentlim](https://twitter.com/residentlim)

[Ariana](https://github.com/Ariana1729)

[Wealthyturtle](https://github.com/Wealthyturtle)

[dbsqwerty](https://github.com/dbsqwerty)

Somehow we (Team CATS SG) got second place in this CTF. 

## Misc Challenges

### Follow

Search for the username on twitter. https://twitter.com/sc4ry_gh0st
This is the message we get. 
```
Ｈｏpe 
ｔhⅰs  ｙear  wіll  be  good.
Happy New Year
```
After doing a quick google search on "Twitter Message Steg", we get this result. https://holloway.nz/steg/

Entering the text into the decoding website yields the flag. 

Flag: ```cybergrabs{tvigt6}```

### Easy!!!
We are given the following text. ```uggcfzrtnamsvyrJLxJ2LMn#0GK1Iy9IWOfAsRCneIh0MOrNTugF8knPAO-nKX2xE7H```
After perfoming ROT13 on it, we notice a url link that after some formatting is https://mega.nz/file/WYkW2YZa#0TX1Vl9VJBsNfEParVu0ZBeAGhtS8xaCNB-aXK2kR7U

After downloading the file, we notice that it is essentially a JPG image hexdump in reverse. So using cyberchef, we reverse the input, decode from hex and lastly render the image. This leads to a blank image. hmmmmmmm

Now at this point, I have solved a few other challenges that all made use of steghide and jpg. As such, I decided to download the image, run it through steghide with no password and we get the flag. 

Flag: ```cybergrabs{fin4lly_y0u_g07_th3_fl4g_nic3_buddy}```

### Salt is the Important incrident

We are given a zip file. Almost immediately, the flag in the zip file turns out to be a false flag. **You will have realised by now that this CTF is full of false flags and that this is very annoying and lowers the experience and fun of the CTF. Dear organisers, never ever put false flags ever again. It is annoying, painful and frankly, there are other ways to indicate that a certain method is not the method to follow when solving.** Back to the challenge, the 2 images found inside the zip files are JPG files. Seeing as this CTF has made use of steghide for so so so many challenges, I decided to run steghide again. This time we are greeted with a flag.pdf that is locked and a hint telling us the password is ```password_author```. Now in the zip file, there is also the following hash ```07176f833cac2a1c539e86744fdcd4d7```. The Challenge description also indicates that the following salt was used ```0namak0``` After running it through hashcat with rockyou.txt, we get the following password ```3205077273lunayoelareina```

As such, our final password to access the pdf file is ```3205077273lunayoelareina_x3rz```
In the pdf, we finally get our flag. 

Flag: ```cybergrabs{Y0u_n4il3d_it_eW91bmFpbGVkaWl0}```



### Wonderful Colours

We are presented with an image file,
![](https://i.imgur.com/2ywFyDS.png)
After a simple Google search for ``color cipher``, we find that the image is using the Hexahue Alphabet (https://www.boxentriq.com/code-breaking/hexahue). After decoding with the given alphabet list, we get the text ``w3h4ck3d1t``, and thus the flag is ``cybergrabs{w3h4ck3d1t}``.


## REV Challenges

### Reverseenc0

Open the binary up in IDA, check String window. Binary is packed with UPX, so we run `upx -d` to unpack it. Using `ldd` to check the shared library dependencies, the binary depends on `libgo.so.13`. Therefore, this is a Golang binary.

Golang binaries have an entry point at `main_main`, so we can trace execution from there. Before the flag is shown in `main_notmain+4FA`, the string "revpwn" is moved onto the stack. 

```nasm
mov     byte ptr [rbp-226h], 72h ; 'r'
mov     byte ptr [rbp-225h], 65h ; 'e'
mov     byte ptr [rbp-224h], 76h ; 'v'
mov     byte ptr [rbp-223h], 70h ; 'p'
mov     byte ptr [rbp-222h], 77h ; 'w'
mov     byte ptr [rbp-221h], 6Eh ; 'n'
```

Then, the methods `_runtime_slicebytetostring`, `_runtime_slicestringtobyte` and `_encoding_hex_EncodeToString` are called on the string.

After checking the documentation for those Golang functions, we can infer that the flag is "revpwn" converted to hex representation.

```
"revpwn" --> "72657670776e" --> cybergrabs{72657670776e}
```

### GOOFYSYS

Literally the same process as Reverseenc0. You don't need to care about any of the checks. Just find where the flag is printed, get the string that is moved onto the stack and convert to hex representation.

```
"string" --> "737472696e67" --> cybergrabs{737472696e67}
```

References:
https://medium.com/@nishanmaharjan17/reversing-golang-binaries-part-1-c273b2ca5333
https://x0r19x91.gitlab.io/post/reversing-go-part-1/

## Crypto Challenges

### W4rm_up

We are provided with a text file containing
```
@$$@@@$$@$$$$@@$@$$@@@$@@$$@@$@$@$$$@@$@@$$@@$$$@$$$@@$@@$$@@@@$@$$@@@$@@$$$@@$$@$$$$@$$@$$$@@@$@$$$@$@$@$$@$@@$@$$$@$@@@@$$@@$$@$@$$$$$@$$@@$$$@@$$@@@@@@$$@@@@@$$@@$@@@$@$$$$$@$$$@$$$@@$$@$@@@$$$@@$@@$$@$$@$@$$$@$@$@$$$@@@@@$@$$$$$@$$@$@@$@$$$@@$$@$$@$$$@@@$@@$$$@$$$@$@@@$@$$$$$@$$@$@@$@$$$@$@@@$$$$$@$
```
As the ciphertext only contains 2 symbols, it means that the ciphertext can be represented in binary. By replacing ``@`` with ``0``, and ``$`` with ``1``, we get
```
0110001101111001011000100110010101110010011001110111001001100001011000100111001101111011011100010111010101101001011101000011001101011111011001110011000000110000011001000101111101110111001101000111001001101101011101010111000001011111011010010111001101101110001001110111010001011111011010010111010001111101
```
Converting from binary to ASCII, we get the flag ``cybergrabs{quit3_g00d_w4rmup_isn't_it}``.

### What is Secret message

We are provided with a partial credit card number, ``543******5251849``. According to Wikipedia (https://en.wikipedia.org/wiki/Payment_card_number), most credit cards use Luhn's algorithm for validation.

As there are only 6 missing digits, we can brute force all of them to see which credit card numbers are valid. In addition, as we are provided the hint that the credit card number is divisible by 53451, we can reduce the total number of possible credit card numbers to 2 with the following code:
```cpp
#include<bits/stdc++.h>
using namespace std;

bool checkLuhn(string purportedCC) {
    int sum = purportedCC[15] - '0';
    int nDigits = 16;
    int parity = 16 % 2;
    for(int i = 0; i < nDigits-1; i++){
    	int digit = purportedCC[i] - '0';
    	if(i % 2 == parity){
    		digit *= 2;
		}
		if(digit > 9){
			digit -= 9;
		}
		sum += digit;
	}
    return (sum % 10) == 0;
}

string pad(int i){
	string s = to_string(i);
	while(s.length() < 6){
		s = "0" + s;
	}
	return s;
}

int main(){
	for(int i = 0; i <= 999999; i++){
		//543******5251849
		string s = "543" + pad(i) + "5251849";
		if(checkLuhn(s) && stoll(s) % 53451 == 0){
			cout << s << "\n";
		}
	}
}
```

At which point we get that the only valid credit card numbers are:
```
5434511245251849
5435045755251849
```

Credit card numbers have a specific format:
[6 digit Issuer Identifier Numbers][9 digit Account Number][1 digit Checksum]
hence the possible account numbers are
```
124525184
575525184
```

which we can use as password to unlock the pastebin.


Now we are presented with this. 
```
My one friend created one crypto technique in the memory of Lucid Cucumber 4. He challenge me to get the message by decoding it as you all know how bad I am bad at crypto and I know you are Born to be best crypto analyst of the era and you can decode it for me. 
 
He gave me some stuff with cipher text also may it help you :)
 
It give me one key "igqehmd48pvxrl7k36y95j2sfnbo#wc_ztauT" and something Noncense "fizz2swizz".
 
CIPHER : "t4tmrvs9_k6vang76jj_rudxovvn6ar_zi4i8o3yqqql6eyannn_"
 
If you reached here I can bet you will decode it TRY HARDER !!!!!!!!!
```

Now we know that the word "Noncense" seems to be implying "nonce", which is used in the LC4 Cryptosystem. So lets decrypt it.
```python
import lc4
key = "igqehmd48pvxrl7k36y95j2sfnbo#wc_ztauT"
nonce = "fizz2swizz"
cipher = "t4tmrvs9_k6vang76jj_rudxovvn6ar_zi4i8o3yqqql6eyannn_"
flag = lc4.decrypt(key,cipher,nonce)
print(flag)
```
Flag: ```cybergrabs{th4nks_buddy_you_are_great_enjoy_with_my_credit_card}```



### Easiest One

We are given a Chall.wav file. Upon inspection with Audacity,
![](https://i.imgur.com/u0tVE28.png)
It appears that there are multiple bars, which suggests that the wav file is containing morse code.

To decipher the morse code, the wav file is uploaded onto https://morsecode.world/international/decoder/audio-decoder-adaptive.html, where the audio is decoded as ``1S TH1S A M0RS3 C0D3?``, thus the flag is ``cybergrabs{1S TH1S A M0RS3 C0D3?}``.

### Everyone Interested in My Secret Life

We are given the following text. ```eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmbGFnIjoiY3liZXJncmFic3tOMHRfVDAwXzM0c1l9In0.I4zPop1KDT55QOE_QlEi-jh5TXg8nRjbnbDwq2VG1M8```
Looks like a JWT token. Using [jwtcat.py](https://github.com/aress31/jwtcat), we realise that the JWT token is vulnerable to HS256 guessing attacks. From past CTF experience, this means that we should be able to run a brute force/dictionary attack against the token. So lets use [jwt_tool.py](https://github.com/ticarpi/jwt_tool) and rockyou.txt against it. However, by running ```python3 jwt_tool.py -d /usr/share/wordlist/rockyou.txt```, all we get is 
```
Token payload values:                                                    
[+] flag = "cybergrabs{N0t_T00_34sY}"
```
This however is not the flag at all. After looking at the challenge name again, I thought of trying to find out the key HMAC-SHA token. After running it through jwt tool again, we get the key ```perrademierda```
Flag: ```cybergrabs{perrademierda}```


### Insane Encryptiton Technique

The code does a pretty straightforward encryption - hash each character one at a time and shift each of them by a constant amount. Furthermore, since the code uses the hex encoded hash, the character set before the shift is very limited, only 0-9a-f. With this information, we can easily find the shift to be 24 and with this, we decode the ciphertext with a simple lookup table:

```python=
import hashlib
import random

hashtbl = {}
secret = 24
for i in range(256):
    enc = ""
    hashed = hashlib.sha256(chr(i)).hexdigest()
    for j in hashed:
        new_code = chr(ord(j) + secret)
        enc+=str(new_code)
    hashtbl[enc] = chr(i)
f = open("enc.txt","r").read().replace("\n","")
sol = ""
for i in range(0,len(f),64):
    sol += hashtbl[f[i:i+64]]
print sol
```

Output: `we are going to paste this you can also try it jT01mdUQ`

This suggests that we visit a [pastebin link](https://pastebin.com/jT01mdUQ). On the pastebin, we find some base-64 encoded message and a pub file that looks like a RSA key. The values of `n` and `e` are

```
n = 658794619177310056199188828886255847078213856198770072531279970640284839403939027580419930490971954742802532594198535050570553464575789046211913820345844707978754338455532456617022546915145481301004455440365318897974855267989361115864756268988784420613943490029396181997630129506271592216915256776744480840784608636350565837640216047060091709391260145583402384593061472214504634271795762848059531668616848361959878576445405318195276215561531091561879657615741416716941207881172575295389286367653570320591885345679452040703912984584440625037349875813651966612907832034258746133750417255589866102616209306899810117648840659269541629391493483101631651027227476454344920584421697542324370531225990940393645636879157869782441604079666600942252379753050549676527148999842155550769847164331925394324341798651561436225989036242629041271794160257735929413904116675722995967609935436137085800939119084154714667692480135099667092519545908615660862933749214236702850561325374906055189201961952057447094433705907026859871342842440489928732622169542436396912898777305646041593010774196731634138884474655285436780821925289872156203225365914697928823021266425348095968492670730662793174675019311014924945482387496897727314472097951901654469994790999
e = 65537
```

which unfortunately turns out to be too hard to factorize. However, it turns out that if we treat `e` as the private exponent and decrypt the message, it works!:

```
sage: hex(pow(c,e,n))
'0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00637962657267726162737b5930755f50726f7633445f4d335f5772306e475f3a287d'
sage: chr(0x637962657267726162737b5930755f50726f7633445f4d335f5772306e475f3a287d)
cybergrabs{Y0u_Prov3D_M3_Wr0nG_:(}
```

## OSINT Challenges

### r3c0n

In the challenge description, we are not provided with much information, except for the challenge author, sc4ry_gh0st, who is presumably the OSINT target.

Upon entering ``sc4ry_gh0st`` into Google, we get a GitHub page: https://github.com/sc4rygh0st which contains only 1 repository, which has 12 commits that contain a few possible flags.

After going through the commits, and some trial and error, the correct flag text is found at https://github.com/sc4rygh0st/sc4rygh0st.github.io/commit/aa502dc01a95f333939b90c05905e6776bb49fa5, and thus the flag is ``cybergrabs{1_4m_n00b}``.

### Blue Moon

We are provided with an image of the book titled "Blue Moon".
![](https://i.imgur.com/qNQISdR.jpg)

Where presumably, the bottom text of "Habiba B" is the author of said book. Upon googling ``Habiba B blue moon``, we find the Amazon page where this book is sold, at https://www.amazon.com/Blue-Moon-Habiba-B/dp/1718164203.

The description of the book is
```
Blue Moon is a poetry collection surrounding the love of solitude, heartbreak and happiness of the authors journey. The reader will discover the significant experiences that have been encountered; from the exposure of betrayal, the unspoken words, the disappearance of loved ones, to the happiness with those that can never be replaced. See more via @Habi6a on instagram
```
Which implies that the handle of the book's author is ``@Habi6a``.

Now from Amazon, we also know that the publication date of the book was ```August 14, 2018```.

Now there is a hint that states that the author also likes cats. As such, I googled for ```Habiba B cat```. Google yields the following result. https://uk.catinaflat.com/pet-sitter/97907

From this website, we can obtain the following details.
```
Location: Camden Town
Age: 25
```

As such, our final flag is ```cyb3rg4abs{14082018_@Habi6a_Camden_Town_25}```

## Forensics Challenges

### Jasper
Run ``strings`` on the Jasper.jpg image, and you'll get the flag ``cybergrabs{Y0U_4re_g00d_4t_m3ta_DaT4}``.


### Password

We are given a EO1 file. Instincitvely, I ran it through autopsy to see what we can find from the Disk Image file. A few things are noticable, we have a SAM and SYSTEM hive file. The challenge description also says that we are looking for the password of the computer. From past CTF experience, the easiest way to get the password out is either with both the SAM and SYSTEM hives or the LSA process dump. Either method can be passed through mimikatz to extract the NTLM hash. After getting the NTLM hash, we just need to hashcat and find the password. 

Now on to getting the hashes out. After much checking, we realise that the SYSTEM hive is corrupted and unusable. So we need to switch to method 2. After searching for ```lsa```, autopsy returns us this file called ```lsass.dmp```.  Bingo, we got the LSA dump file. 

Now with this, we run it through mimikatz with the following command. 
```sekurlsa::minidump lsass.dmp```
```sekurlsa::LogonPasswords```

From this, we get the following output.
```  [00000003] Primary
         * Username : wolf-pc
         * Domain   : DESKTOP-HT45A62
         * NTLM     : 5e4fbcac3d881933f54371eb10ea221b
         * SHA1     : 4f58ff4a0e138308915a6bee36d142d5bdb6a81e
```
The NTLM is all we need to proceed to cracking the hash. 

After running it through hashcat dictionary attack with rockyou.txt, we get the password ```4hacking```

Flag: ```cybergrabs{4hacking}```

### Secret

Continuing on from Password, we make use of the same disk image file. This time, the challenge description hints us to something he hid on the internet. After looking through the web history and going through multiple false links, we finally find this link. ```https://cryptobin.co/a1o8e8f7``` The password is the same as the one we found above as we are told that he re-uses his password. 

After unlocking the pasted content, we notice immediately that it is in base64 format. So we parse it through cyberchef base64 and it turns out to be a GIF file. Now before rendering the gif file in cyberchef, we notice this strange part. 

(ALT solution, notice the gif is in downloads folder and continue as below after insepecting the gif file)
```
...
<rdf:Description rdf:about=''
  xmlns:dc='http://purl.org/dc/elements/1.1/'>
  <dc:creator>
   <rdf:Seq>
    <rdf:li>Wolf Saar</rdf:li>
   </rdf:Seq>
  </dc:creator>
  <dc:description>
   <rdf:Alt>
    <rdf:li xml:lang='x-default'>cybergrabs{dammm_y0u_f0und_p3p3_h3cker}</rdf:li>
   </rdf:Alt>
  </dc:description>
 </rdf:Description>
</rdf:RDF>
```
Ah ha, there is our flag. 

Flag: ```cybergrabs{dammm_y0u_f0und_p3p3_h3cker}```

### Stargazer

This is also a continuation from the previous challenge. This time we are told that "Mr.Wolf was using some application for his secret Communications find the application and his secret too." From inspecting the apps he downloaded, the most likely application he used for communication was HexChat. After inspecting the HexChat IRC logs, we notice this interesting conversation. 
```
**** BEGIN LOGGING AT Thu Jan  7 05:32:38 2021

Jan 07 05:32:38 *	Now talking on #likes
Jan 07 05:32:38 *	beckett.freenode.net sets mode +n on #likes
Jan 07 05:32:38 *	beckett.freenode.net sets mode +s on #likes
Jan 07 05:32:42 <alpha_wolf>	i like stargazer lily
Jan 07 05:32:47 <alpha_wolf>	and ofcourse wolfs
Jan 07 05:32:49 <alpha_wolf>	:)
**** ENDING LOGGING AT Thu Jan  7 05:32:55 2021
```
Now we also know there is an image called ```stargazer.jpg``` in his pictures folder. So this must mean that stargazer.jpg is where the flag is hiding in. After a quick round of checking it out with exiftool and binwalk, we realise that this must be a stegonography challenge. Usually, most jpg files hide data using steghide. 

By using ```https://aperisolve.fr/```, we know that the password for steghide is ```maybethisthingwillbeusefull```. Lets run it through steghide and we get the flag. 

Flag: ```cybergrabs{d0_y0u_like_stargazer_l1ly???}```

## WEB Challenges

### Baby Web

After poking around the website for a bit, we notice the cookie value. After decoding the cookie from hex and decoding it from base91, we get the following flag.
Flag: ```cybergrabs{v3ryyy_3asy_f0r_y0u_i_gu3ss}```

## SANITY/FEEDBACK

### Welcome, Bot Meet and Feedback Challenge:
Literally just a sanity check. copy pasta flag.

Welcome Challenge : ```cybergrabs{w3lc0m3_t0_ctf}```
Bot Meet Challenge: ```cybergrabs{1_m_n0t_4_h4ck3r}```
Feedback Challenge: ```cybergrabs{TH4NKS_F0R_PL4Y1NG}```
