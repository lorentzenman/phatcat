# phatcat

Phatcat is a wrapper around my common goto options for GPU Cracking monster Hashcat, it attempts to emulate some useability found in John.

If you pass this the rules argument, then it will run all the rules files found in the directory. Path(s) is(are) hardcoded or you can use the custom option.

Much more to follow, but for simple 'use my GPU to bosh this Wordlist quickly...' works really well on test.

v0.1 - Supports wordlists in various formats



Examples

./phatcat.py --paths


       _           _            _   
 _ __ | |__   __ _| |_ ___ __ _| |_ 
| '_ \| '_ \ / _` | __/ __/ _` | __|
| |_) | | | | (_| | || (_| (_| | |_ 
| .__/|_| |_|\__,_|\__\___\__,_|\__|
|_| 
      	       don't purr, roarrrrr!	                                
	
Hashcat Binary             : /root/apps/cudahashcat/cudaHashcat-2.01/./cudaHashcat64.bin
Default Rules Directory    : /root/apps/cudahashcat/cudaHashcat-2.01/rules/
Default Output Directory   : /root/Desktop/


--> Straight wordlist brute force
./phatcat.py --mode password --hashtype ntml --hashfile /root/hashes.txt --wordlist /root/wordlist.txt


--> Custom session and output directory with rules translation
Sets the mode to a password attack using a wordlist for NTLM hashes, outputs to a folder called '/root/audit' (which it will create if this doesn't exist) and creates kraken.pot, kraken.log as the session name, so you can create multple sessions in the same folder. Runs all the rules in the default rules path directory as the '--rules' option has been specified.

./phatcat.py --mode password --session kraken --output /root/audit --hashtype ntml --rules --hashfile /root/hashes.txt --wordlist /root/wordlist.txt

