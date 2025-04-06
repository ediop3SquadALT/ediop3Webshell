# ediop3Webshell
A exploitation tool (webshell)

# for termux install thesee
pkg update -y && pkg install -y curl netcat-openbsd wget coreutils tor openjdk-17 python python-pip && pip install marshalsec && wget -qO ~/ysoserial.jar https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar && git clone https://github.com/ediop3SquadALT/ediop3Webshell && cd ediop3webshell 


# for kali / parrot os
sudo apt update -y && sudo apt install -y curl netcat wget tor openjdk-17-jre python3 python3-pip && pip3 install marshalsec && wget -qO ~/ysoserial.jar https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar && git clone https://github.com/ediop3SquadALT/ediop3Webshell


  # How to Use ediop3Webshell 

Make the script executable by running:
chmod +x ediop3webshell.sh

Basic usage requires a target file (-t) and your webshell (-w):
./ediop3webshell.sh -t targets.txt -w shell.php

For stealth mode with Tor routing, add the -p flag:
./ediop3webshell.sh -t targets.txt -w shell.php -p

To target a specific CVE (like Log4Shell), use the -c option:
./ediop3webshell.sh -t targets.txt -w shell.php -c CVE-2021-44228

For advanced scanning (CVE-2023-47246) with a wordlist:
./ediop3webshell.sh -t targets.txt --scan-cve-2023-47246 paths.txt

To list all available CVEs and payloads:
./ediop3webshell.sh --list-cves
./ediop3webshell.sh --list-payloads

For brute-force upload path discovery:
./ediop3webshell.sh -t targets.txt -w shell.php --upload-wordlist upload_paths.txt

The script will automatically:

  Scan and identify vulnerable systems

  Attempt exploitation using the best available method

  Upload your webshell if successful

  Clean up traces of the attack

  Logs are saved to:

  ediop3_ops.log (visible log)

/var/tmp/.ediophist (hidden log)

For maximum effectiveness:

Use fresh target lists

Customize your webshell

Verify all dependencies are working

Monitor the log files for results
