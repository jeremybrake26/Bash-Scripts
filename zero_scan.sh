#!/bin/bash

function recon()
{
	mkdir $2 2>/dev/null
	host=$(pwd)"/$2"
	cd $host 2>/dev/null
	mkdir $host"/full_scan" 2>/dev/null
	cd $host"/full_scan" 2>/dev/null
	echo "FULL SCAN START"
	echo "***************************************************************"
	nmap -sV -T4 -p- -oA nmap.$1 $2 2>/dev/null
	echo "END OF FULL SCAN"
	echo "***************************************************************"
	
	sleep 3
	echo "VULN SCAN START"
        echo "***************************************************************"
	mkdir $host"/vuln_scan" 2>/dev/null
	cd $host"/vuln_scan" 2>/dev/null
	nmap -sV -T4 -p- --script=vulners -o nmap.vuln.$1 $2 2>/dev/null
	echo "END OF VULN SCAN"
        echo "***************************************************************"
	
	sleep 3
	echo "OS SCAN IDENTIFIER START"
	echo "***************************************************************"
	mkdir $host"/os_scan_identifier" 2>/dev/null
	cd $host"/os_scan_identifier" 2>/dev/null
	echo "Potential Operating Systems and Versions....."
	nmap -T4 -sV -p- -oA nmap.os_identifier.$1 $2 2>/dev/null | grep --color=always 'Linux\|Windows\|OS\|linux\|windows'
	echo "END OF OS SCAN IDENTIFIER"
	echo "***************************************************************"
	
	sleep 3
	echo "UDP SCAN START"
	echo "***************************************************************"
	mkdir $host"/udp_scan" 2>/dev/null
	cd $host"/udp_scan" 2>/dev/null
	nmap -T4 -sUV -p- -F --version-intensity 0 -oA nmap.udp_scan.$1 $2 2>/dev/null
	echo "END OF UDP SCAN"
	echo "***************************************************************"
	
	sleep 3
	echo "NIKTO SCAN START"
        echo "***************************************************************"
        mkdir $host"/nikto_scan" 2>/dev/null
        cd $host"/nikto_scan" 2>/dev/null
	for x in $(cat $host/full_scan/nmap.*.nmap | grep 'tcp\|udp' | cut -d "/" -f 1);
	do
        	nikto -h $2 -p $x -output $host/nikto_scan/nikto_$2_$x.txt
	done
        echo "END OF NIKTO SCAN"
        echo "***************************************************************"
}

function fuzz_recon()
{
	file_name=$(echo $2 | cut -d '/' -f 3)
	mkdir $file_name 2>/dev/null
	mkdir $file_name"/dirb_results" 2>/dev/null
	host=$(pwd)"/$file_name"
	cd $host"/dirb_results" 2>/dev/null
	echo "START DIRB SCAN"
	echo "***************************************************************"
	dirb $2 -o $host/dirb_results/dirb_"$file_name".txt
	echo "END OF DIRB SCAN"
	echo "***************************************************************"

	mkdir $file_name/gibuster_results 2>/dev/null
	host=$(pwd)"/$file_name"
        cd $host"/gobuster" 2>/dev/null
        echo "START GOBUSTER SCAN"
        echo "***************************************************************"
        gobuster dir $2 -o $host/gobuster_results/gobuster_"$file_name".txt
	gobuster vhost -u $2 -o $host/gobuster_results/gobuster_vhost_"$file_name".txt -w /usr/share/seclists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
        echo "END OF GOBUSTER SCAN"
        echo "***************************************************************"
}

function supergrep()
{
grep -D skip --exclude-dir "/run" --color=always -Ri 'user\|password\|username\|pass' / 2>/dev/null
}

if [ $1 = "recon" ] && [ $2 ]; then
	if [ "$EUID" -ne 0 ]; then
		echo "You need to run script as root user!"
	else
		clear
		recon "$1" "$2"
	fi
elif [ $1 = "fuzz" ] && [ $2 ]; then
	clear
	fuzz_recon "$1" "$2"
elif [ $1 = "supergrep" ]; then
	supergrep
else
	clear
	echo "Please type a command...."
	echo "***********************************************************************************"
	echo "* <Help> ./zero_scan.sh help (for help)                                           *"
	echo "* <Recon> ./zero_scan.sh recon (recon machine)                                    *"
	echo "* <Fuzzing> ./zero_scan.sh fuzz (fuzzing)                                         *"
	echo "* <All> ./zero_scan.sh all (scans for all recon)                                  *"
        echo "* <Supergrep> ./zero_scan.sh supergrep (Super Grep for Usernames and Passwords)   *"
	echo "*                 C@pSc@n                                                         *"
	echo "*             BY: C@pt@inZ3r0                                                     *"
	echo "***********************************************************************************"
fi
