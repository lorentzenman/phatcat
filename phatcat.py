#!/usr/bin/python
# Author : Matt Lorentzen
# adds a wrapper around the common hashcat options -- mainly wordlist options, rules 

import argparse
import os
import sys


def banner():
	banner = """

       _           _            _   
 _ __ | |__   __ _| |_ ___ __ _| |_ 
| '_ \| '_ \ / _` | __/ __/ _` | __|
| |_) | | | | (_| | || (_| (_| | |_ 
| .__/|_| |_|\__,_|\__\___\__,_|\__|
|_| 
      	       don't purr, roarrrrr!	                                
	"""	
	print yellowtxt(banner)


def run_hashcat(command):
	""" The main function to call hashcat """
	os.system(command)

	

def list_hash_values():
	""" Default hashcat supported hashes """
	hashes = """

[[ Operating-Systems ]]

   3000 = LM
   1000 = NTLM
   1100 = Domain Cached Credentials (DCC), MS Cache
   2100 = Domain Cached Credentials 2 (DCC2), MS Cache 2
  12800 = MS-AzureSync PBKDF2-HMAC-SHA256
   1500 = descrypt, DES(Unix), Traditional DES
  12400 = BSDiCrypt, Extended DES
    500 = md5crypt $1$, MD5(Unix)
   3200 = bcrypt $2*$, Blowfish(Unix)
   7400 = sha256crypt $5$, SHA256(Unix)
   1800 = sha512crypt $6$, SHA512(Unix)
    122 = OSX v10.4
    122 = OSX v10.5
    122 = OSX v10.6
   1722 = OSX v10.7
   7100 = OSX v10.8
   7100 = OSX v10.9
   7100 = OSX v10.10
   6300 = AIX {smd5}
   6700 = AIX {ssha1}
   6400 = AIX {ssha256}
   6500 = AIX {ssha512}
   2400 = Cisco-PIX
   2410 = Cisco-ASA
    500 = Cisco-IOS $1$
   5700 = Cisco-IOS $4$
   9200 = Cisco-IOS $8$
   9300 = Cisco-IOS $9$
     22 = Juniper Netscreen/SSG (ScreenOS)
    501 = Juniper IVE
   5800 = Android PIN
   8100 = Citrix Netscaler
   8500 = RACF
   7200 = GRUB 2
   9900 = Radmin2


[[ Roll-your-own: Raw Hashes ]]

    900 = MD4
      0 = MD5
   5100 = Half MD5
    100 = SHA1
  10800 = SHA-384
   1400 = SHA-256
   1700 = SHA-512
   5000 = SHA-3(Keccak)
  10100 = SipHash
   6000 = RipeMD160
   6100 = Whirlpool
   6900 = GOST R 34.11-94
  11700 = GOST R 34.11-2012 (Streebog) 256-bit
  11800 = GOST R 34.11-2012 (Streebog) 512-bit

[[ Roll-your-own: Iterated and / or Salted Hashes ]]

     10 = md5($pass.$salt)
     20 = md5($salt.$pass)
     30 = md5(unicode($pass).$salt)
     40 = md5($salt.unicode($pass))
   3800 = md5($salt.$pass.$salt)
   3710 = md5($salt.md5($pass))
   2600 = md5(md5($pass)
   4300 = md5(strtoupper(md5($pass)))
   4400 = md5(sha1($pass))
    110 = sha1($pass.$salt)
    120 = sha1($salt.$pass)
    130 = sha1(unicode($pass).$salt)
    140 = sha1($salt.unicode($pass))
   4500 = sha1(sha1($pass)
   4700 = sha1(md5($pass))
   4900 = sha1($salt.$pass.$salt)
   1410 = sha256($pass.$salt)
   1420 = sha256($salt.$pass)
   1430 = sha256(unicode($pass).$salt)
   1440 = sha256($salt.unicode($pass))
   1710 = sha512($pass.$salt)
   1720 = sha512($salt.$pass)
   1730 = sha512(unicode($pass).$salt)
   1740 = sha512($salt.unicode($pass))

[[ Network protocols, Challenge-Response ]]

     23 = Skype
   2500 = WPA/WPA2
   4800 = iSCSI CHAP authentication, MD5(Chap)
   5300 = IKE-PSK MD5
   5400 = IKE-PSK SHA1
   5500 = NetNTLMv1
   5500 = NetNTLMv1 + ESS
   5600 = NetNTLMv2
   7300 = IPMI2 RAKP HMAC-SHA1
   7500 = Kerberos 5 AS-REQ Pre-Auth etype 23
   8300 = DNSSEC (NSEC3)
  10200 = Cram MD5
  11100 = PostgreSQL Challenge-Response Authentication (MD5)
  11200 = MySQL Challenge-Response Authentication (SHA1)
  11400 = SIP digest authentication (MD5)

[[ Roll-your-own: Authenticated Hashes ]]

     50 = HMAC-MD5 (key = $pass)
     60 = HMAC-MD5 (key = $salt)
    150 = HMAC-SHA1 (key = $pass)
    160 = HMAC-SHA1 (key = $salt)
   1450 = HMAC-SHA256 (key = $pass)
   1460 = HMAC-SHA256 (key = $salt)
   1750 = HMAC-SHA512 (key = $pass)
   1760 = HMAC-SHA512 (key = $salt)

[[ Generic KDF ]]

    400 = phpass
   8900 = scrypt
  11900 = PBKDF2-HMAC-MD5
  12000 = PBKDF2-HMAC-SHA1
  10900 = PBKDF2-HMAC-SHA256
  12100 = PBKDF2-HMAC-SHA512

[[ Forums, CMS, E-Commerce, Frameworks, Middleware, Wiki, Management ]]

    121 = SMF (Simple Machines Forum)
    400 = phpBB3
   2611 = vBulletin < v3.8.5
   2711 = vBulletin > v3.8.5
   2811 = MyBB
   2811 = IPB (Invison Power Board)
   8400 = WBB3 (Woltlab Burning Board)
     11 = Joomla < 2.5.18
    400 = Joomla > 2.5.18
    400 = Wordpress
   2612 = PHPS
   7900 = Drupal7
     21 = osCommerce
     21 = xt:Commerce
  11000 = PrestaShop
    124 = Django (SHA-1)
  10000 = Django (PBKDF2-SHA256)
   3711 = Mediawiki B type
   7600 = Redmine

[[ Database Server ]]

     12 = PostgreSQL
    131 = MSSQL(2000)
    132 = MSSQL(2005)
   1731 = MSSQL(2012)
   1731 = MSSQL(2014)
    200 = MySQL323
    300 = MySQL4.1/MySQL5
   3100 = Oracle H: Type (Oracle 7+)
    112 = Oracle S: Type (Oracle 11+)
  12300 = Oracle T: Type (Oracle 12+)
   8000 = Sybase ASE

[[ HTTP, SMTP, LDAP Server]]

    141 = EPiServer 6.x < v4
   1441 = EPiServer 6.x > v4
   1600 = Apache $apr1$
  12600 = ColdFusion 10+
   1421 = hMailServer
    101 = nsldap, SHA-1(Base64), Netscape LDAP SHA
    111 = nsldaps, SSHA-1(Base64), Netscape LDAP SSHA
   1711 = SSHA-512(Base64), LDAP {SSHA512}

[[ Checksums ]]

  11500 = CRC32

[[ Enterprise Application Software (EAS) ]]

   7700 = SAP CODVN B (BCODE)
   7800 = SAP CODVN F/G (PASSCODE)
  10300 = SAP CODVN H (PWDSALTEDHASH) iSSHA-1
   8600 = Lotus Notes/Domino 5
   8700 = Lotus Notes/Domino 6
   9100 = Lotus Notes/Domino 8
    133 = PeopleSoft

[[ Archives ]]

  11600 = 7-Zip
  12500 = RAR3-hp

[[ Full-Disk encryptions (FDE) ]]

   62XY = TrueCrypt 5.0+
     X  = 1 = PBKDF2-HMAC-RipeMD160
     X  = 2 = PBKDF2-HMAC-SHA512
     X  = 3 = PBKDF2-HMAC-Whirlpool
     X  = 4 = PBKDF2-HMAC-RipeMD160 + boot-mode
      Y = 1 = XTS  512 bit (Ciphers: AES or Serpent or Twofish)
      Y = 2 = XTS 1024 bit (Ciphers: AES or Serpent or Twofish or AES-Twofish or Serpent-AES or Twofish-Serpent)
      Y = 3 = XTS 1536 bit (Ciphers: All)
   8800 = Android FDE < v4.3
  12200 = eCryptfs

[[ Documents ]]

   9700 = MS Office <= 2003 MD5 + RC4, oldoffice$0, oldoffice$1
   9710 = MS Office <= 2003 MD5 + RC4, collider-mode #1
   9720 = MS Office <= 2003 MD5 + RC4, collider-mode #2
   9800 = MS Office <= 2003 SHA1 + RC4, oldoffice$3, oldoffice$4
   9810 = MS Office <= 2003 SHA1 + RC4, collider-mode #1
   9820 = MS Office <= 2003 SHA1 + RC4, collider-mode #2
   9400 = MS Office 2007
   9500 = MS Office 2010
   9600 = MS Office 2013
  10400 = PDF 1.1 - 1.3 (Acrobat 2 - 4)
  10410 = PDF 1.1 - 1.3 (Acrobat 2 - 4) + collider-mode #1
  10420 = PDF 1.1 - 1.3 (Acrobat 2 - 4) + collider-mode #2
  10500 = PDF 1.4 - 1.6 (Acrobat 5 - 8)
  10600 = PDF 1.7 Level 3 (Acrobat 9)
  10700 = PDF 1.7 Level 8 (Acrobat 10 - 11)

[[ Password Managers ]]

   9000 = Password Safe v2
   5200 = Password Safe v3
   6800 = Lastpass
   6600 = 1Password, agilekeychain
   8200 = 1Password, cloudkeychain
  11300 = Bitcoin/Litecoin wallet.dat
  12700 = Blockchain, My Wallet
	
	"""	
	return hashes




#----[ Helper Functions ] --------------------------------------------------

def redtxt(text2colour):
	redstart = "\033[0;31m"
	redend = "\033[0m"
	return redstart + text2colour + redend

def greentxt(text2colour):
	greenstart = "\033[0;32m"
	greenend = "\033[0m"
	return greenstart + text2colour + greenend

def yellowtxt(text2colour):
	yellowstart = "\033[0;33m"
	yellowend = "\033[0m"
	return yellowstart + text2colour + yellowend

def bluetxt(text2colour):
	bluestart = "\033[0;34m"
	blueend = "\033[0m"
	return bluestart + text2colour + blueend


#----[ Main Function ]------------------------------------------------------

def Main():
	banner()
	hashcat_path = '/root/apps/cudahashcat/cudaHashcat-2.01/./cudaHashcat64.bin'
	rules_path = '/root/apps/cudahashcat/cudaHashcat-2.01/rules/'		
	default_output_path = '/root/Desktop/'	
	
	# ---- [ Parser Setup ] ------------------------------------------------
	parser = argparse.ArgumentParser(description="Phatcat is a wrapper around the common goto options for Hashcat, it attempts to emulate some useability found in John.")
	parser.add_argument("--mode",  help='The mode option - <password> <bruteforce>')
	parser.add_argument("--paths", action='store_true', default=False, help="Prints default paths")
	parser.add_argument("--session", help='Name of session')
	parser.add_argument("--output", help='Specify custom output file location')
	
	# create hash options	
	hash_options = parser.add_argument_group('Hash Configuration Settings')
	hash_options.add_argument("--hashfile", help='File containing hashes')
	hash_options.add_argument("--hashtype", help='<ntlm> <lm> <netlmv2> <netntlmv2> will work or number value when calling --show_hashtypes')
	hash_options.add_argument("--show_hashtypes", action='store_true', default=False, help="Lists all avaliable hash options")
	
	# create the password wordlist options
	password_options = parser.add_argument_group('Wordlist Based Password Options')
	password_options.add_argument("--wordlist", help='Path to wordlist')
	password_options.add_argument("--rules", action='store_true', default=False, help='Run the rules files in the default rules location (see --paths)')
	password_options.add_argument("--rules_path", help='Custom Path to directory with rule files if overiding the default rules location')

	# checks supplied args number and prints help
	if len(sys.argv)==1:
		parser.print_help()
		sys.exit(1)
	# now count arguments
	args = parser.parse_args()

	# ---- [ Checks for Path Prints ] -----------------------------------------
	if args.show_hashtypes:
		print list_hash_values()
		sys.exit(1)
	
	if args.paths:
		print("Hashcat Binary             : " + bluetxt(hashcat_path))
		print("Default Rules Directory    : " + bluetxt(rules_path))	
		print("Default Output Directory   : " + bluetxt(default_output_path))
		sys.exit(1)
	
	# ---- [ Build command ] --------------------------------------------------
	command = hashcat_path

	if args.session:
		session_name = args.session
		command = command + " --session=" + session_name
		
	if args.mode.lower() == "password":
		mode = " -a 0"
	hashfile = args.hashfile
	hashtype = args.hashtype
	
	command = command + " " + mode
	
	# now if statements to check supplied args
	if hashtype == "ntlm":
		hashtype_value = "-m 1000"
	elif hashtype == "lm":
		hashtype_value = "-m 3000"
	elif hashtype == "netlmv1":
		hashtype_value = "-m 5500"
	elif hashtype == "netntlmv2":
		hashtype_value = "-m 5600"
	else:
		hashtype_value = "-m " + hashtype
	
	if args.wordlist:
		wordlist = args.wordlist
	
	#if args.hashtype:
	#	hashtype = args.hashtype
	
	command = command + " " + hashtype_value

	# check for output option
	if args.output:
		output = args.output
		if not output.endswith("/"):
			output = output + "/"
		if not os.path.isdir(output):
			os.makedirs(output)
		os.chdir(output)
			
	else:
		os.chdir(default_output_path)
	# specifies outfile text option, and format in file as user:password
	command = command + " --outfile cracked.txt --outfile-format 2 --username"

	
	# check for rules option and run command
	if args.rules == True:
		if args.rules_path:
			# "run hashcat with custom rules path"
			rules_path = args.rules_path
			if not rules_path.endswith("/"):
				rules_path = rules_path + "/"
		else:
			# "run hashcat with default path"
			for rule_file in os.listdir(rules_path):
				rule_file = rules_path + rule_file
				#print command
				run_hashcat(command + " " + "-r " + rule_file + " " + hashfile + " " + wordlist)
	else:			
		# run hashcat without rules loop.
		command = command + " " + hashfile + " " + wordlist
		#rint command
		run_hashcat(command)

if __name__ == "__main__":
	Main()
