#!/bin/bash

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# SIEM-Less Script Written to fulfill STI 5401 requirement
# Author:	David L. Conner Jr.
# Date: 	February 4, 2019
# Version:	0.01
# Comments:	Tested only on Xubuntu 16.04
#			26 MB no payload pcap 50.284s to process
#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

# Variables
#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
adatetime=$(date +"%y-%m-%d-%H:%M")									# date and time
adate=$(date +"%y-%m-%d")											# date
areport="$adatetime-SIEM-Less.html"									# report file name
whereami=$(pwd)														# current working directory
asilk="$adate-SIEM-Less.silk"										# silk file name
enetwork="Well that address isn't quite right!"						# network error
gotdump=0															# flag to tcpdump or not
gotbro=0															# flag to bro or not
gotsilk=0															# flag to silk or not
conn_log="conn.log"													# lets not bro/process the pcap file every time
div1open="<div style=\"width:600px; margin:50px auto;\"><center><b"	# opening first div
div1finish="</b></center>"											# finish the first div
div2open="<div style=\"background:"									# opening second div
div2finish="; border: 1pt solid black;\">"							# finish the second div
divclose="</div></div>"												# closing div
tableopen="<table align='center'>"									# opening a table
tableclose="</table>"												# closing a table

# Functions
#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

# Check to make sure the required programs are installed
chkprograms(){
	if !(command -v "$1" >/dev/null 2>&1;) then
		echo >&2 "$2"
		echo -n "Type Y to continue or N to abort and press [ENTER]: "
		read goodtogo
		let "$3"=1

		if [ "${goodtogo^n}" = "N" ]; then
			exit
		fi
	fi
}

# Try and make a graceful if not informative landing?
badnews(){
	echo "&nbsp;<br>&nbsp;<br>" >&4
	echo "<font color="red" size="+1">Well... "$1" created an error at line "$2".<br>" >&4
	echo "Moving on to process the next bit of data.</font>" >&4
	echo "&nbsp;<br>&nbsp;<br>" >&4
}

# Check to see if all the inputs have been specified
# Filename, PCAP format, Network e.g. 192.168.1.0, Subnet e.g. 24"
echo -n "Please enter a PCAP file name and press [ENTER]: "
read afilename

# Check to see if file actuall exists
if [ ! -f "$afilename" ]; then
	echo -en "\a"
    echo "Ooops, please confirm that you entered the correct filename!"
	exit
fi

# Check to see if file is PCAP
atype=$(file "$afilename")
if !(echo "$atype" | grep -i "pcap") ; then
	echo -e "\a"
    echo "Sorry, that doesn't appear to be a PCAP file?"
	exit
fi

# Get the network value and validate it
echo -n "Please enter a network, e.g. 192.168.1.0 and press [ENTER]: "
read anetwork
	
# First off the last octet needs to be a zero
octets=(${anetwork//./ })

# Is the last octect zero
if [[ "${octets[3]}" -eq 0 ]]; then
	# now does the rest of the network value look like its supposed to
	if !([[ $anetwork =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]); then
		echo "$enetwork"
		echo "Your network should be four integers between 0 and 255 each separated by a period."
		exit
	fi
else
	echo "$enetwork The last value needs to be zero."
	exit
fi

# Is the subnet an expected value
echo -n "Please enter a subnet, e.g. 24 and press [ENTER]: "
read asubnet
if !([ "$asubnet" -ge 8 ] && [ "$asubnet" -le 30 ]); then
	echo -e "\a"
    echo "Hmmm, that doesn't appear to be a valid subnet?"
	echo "Depending upon the network class this should be a value between 8 and 30."
	exit
fi

# Check to see if tcpdump is present
chkprograms "tcpdump" "Well that's not going to work, tcpdump isn't istalled?" gotdump

# Check to see if Bro is present
chkprograms "bro" "Where's Bro? Please run the following command: sudo apt-get update && sudo apt-get install broctl bro-common bro-aux" gotbro

# Check to see if Silk is present
chkprograms "rwstats" "It doesn't look like SiLK is installed?" gotsilk

# Open report file and add beginning HTML particulars
exec 4>$areport
echo "<html><title>SIEM-Less Network Forensics $adatetime</title><head></head><body>" >&4

# A little padding and title on the top please
echo "<br>" >&4
echo "<center>" >&4
echo "<h2>SIEM-Less Network Forensics</h2>" >&4
echo "<h3>$adatetime</h3>" >&4
echo "</center>" >&4

# Process file with tcpdump for MAC Address data
#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Add beginning DIV particulars and title
echo "$div1open>Unique MAC Adresses in the $anetwork Network$div1finish" >&4
echo "$div2open silver$div2finish<center>" >&4

# tcpdump exists so keep processing
if [ "$gotdump" -eq 0 ]
then
	# Actual tcpdump processing
	# echo "Tcpdump-ish/MAC Addresses happened here!" >&4
	getdump=$(tcpdump -r $afilename -e src net $anetwork/$asubnet | cut -d ' ' -f 2 | sort | uniq)

	# If things are hunky dory then process the results in a legible manner and write to the report file
	# If not then produce an informative error message
	if [ $? -eq 0 ]
	then
		getdump="$(echo "$getdump" | awk '{tdump=$1"<br>"; print tdump}')"
		echo "$getdump" >&4
	else
		badnews "tcpdump or this script" "$LINENO" "$getdump"
	fi
else
	echo "<center>" >&4
	echo "Skipping tcpdump processing!" >&4
fi

# Add closing HTML particulars
echo "</center>$divclose" >&4

# Process file with bro for chatty cathy kevin data
#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Add beginning DIV particulars and title
echo "$div1open>\"Chatty Cathy/Kevin\" (most packets) in the $anetwork Network$div1finish" >&4
echo "$div2open aqua$div2finish" >&4

# Bro exists so keep processing
if [ "$gotbro" -eq 0 ];
then
	# If necessary process pcap file with Bro for the second set of data
	# which means you might want to do this in a separate directory
	# so you don't get files mixed up
	if [ ! -e "$conn_log" ];
	then
		bro -r $afilename
	fi

	# No errors so lets giddyup
	if [ $? -eq 0 ]
	then
		# Process conn.log to ferret out chattiest
		chatty=$(cat conn.log | bro-cut -d id.orig_h id.resp_h  | sort | uniq -c | sort -nr)
		#echo "Something bro-ish/chatty cathy/kevin happened here!" >&4

		# For presentation purposes open a table and add a header
		echo "$tableopen" >&4
		echo "<tr><td><center><b>Count</b></center></td><td><center><b>Source</b></center></td><td><center><b>Destination</b></center></td></tr>" >&4

		# Process the results in a legible manner and write to the report file
		chatty="$(echo "$chatty" | awk '{chat="<tr><td>"$1"</td><td>"$2"</td><td>"$3"</td></tr>"; print chat}')"
		echo "$chatty" >&4

		# Add closing HTML particulars
		echo "$tableclose" >&4
		echo "$divclose" >&4

		# Add beginning DIV particulars and title
		echo "$div1open>Who talks the longest in the $anetwork Network$div1finish" >&4
		echo "$div2open dodgerblue$div2finish" >&4

		# Process conn.log to ferret out long talkers
		talkers_long=$(cat conn.log | bro-cut -d duration id.orig_h id.resp_h | sort -nr)

		# For presentation purposes open a table and add a header
		echo "$tableopen" >&4
		echo "<tr><td><center><b>Duration</b></center></td><td><center><b>Source</b></center></td><td><center><b>Destination</b></center></td></tr>" >&4

		# Process the results in a legible manner and write to the report file
		talkers_long="$(echo "$talkers_long" | awk '{tl="<tr><td>"$1"</td><td>"$2"</td><td>"$3"</td></tr>"; print tl}')"
		echo "$talkers_long" >&4

		# Add closing HTML particulars
		echo "$tableclose" >&4
		echo "$divclose" >&4

		# Add beginning DIV particulars and title
		echo "$div1open>Who sends the most data (bytes) in the $anetwork Network$div1finish" >&4
		echo "$div2open lightseagreen$div2finish" >&4

		# Process conn.log to ferret out who sends the most data
		most_volume=$(cat conn.log | bro-cut -d orig_bytes id.orig_h id.resp_h | sort -nr)

		# For presentation purposes open a table and add a header
		echo "$tableopen" >&4
		echo "<tr><td><center><b>Volume</b></center></td><td><center><b>Source</b></center></td><td><center><b>Destination</b></center></td></tr>" >&4

		# Process the results in a legible manner and write to the report file
		most_volume="$(echo "$most_volume" | awk '{vol="<tr><td align='right'>"$1"&nbsp;&nbsp;</td><td>"$2"</td><td>"$3"</td></tr>"; print vol}')"
		echo "$most_volume" >&4

		# Add closing table particulars
		echo "$tableclose" >&4
	else
		badnews "Bro or this script" "$LINENO" "$getdump"		
	fi
else
	echo "<center>" >&4
	echo "Skipping Bro processing!" >&4
fi

# Add closing DIV particulars
echo "</center>$divclose" >&4

# Process file with SiLK
#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Add HTML beginning DIV particulars and title
echo "$div1open>The Packets in the $anetwork Network Go To These Countries$div1finish" >&4
echo "$div2open orange$div2finish" >&4

# SiLK exists so keep processing
if [ "$gotsilk" -eq 0 ];
then
	# If necessary process pcap file with SiLK for the third set of data
	# which means you might want to do this in a separate directory
	# so you don't get output from other pcaps mixed up
	if [ ! -e "$asilk" ];
	then
		rwp2yaf2silk --in=$afilename --out=$asilk
	fi

	# No errors so lets giddyup
	if [ $? -eq 0 ]
	then
		# Initialize SiLK GeoIP analysis
		silkgeoip=$(rwuniq lbl-ftp.silk --fields=scc --bytes --flows --packets --dip-distinct --no-title | sort -nr -k 2)

		# There's output so lets giddyup
		if [ -n "$silkgeoip" ]
		then
			# For presentation purposes open a table and add a header
			echo "$tableopen" >&4
			echo "<tr><td><center><b>Destination</b></center></td><td><center><b>Bytes</b></center></td><td><center><b>Flows</b></center></td><td><center><b>Packets</b></center></td><td><center><b>Uniq Dest</b></center></td></tr>" >&4

			# Process the results in a legible manner and write to the report file
			silkgeoip="$(echo "$silkgeoip" | awk '{vol="<tr><td align='right'>"$1"</td><td align='right'>"$2"</td><td align='right'>"$3"</td><td align='right'>"$4"</td><td align='right'>"$5"</td></tr>"; print vol}')"

			# Ditch the pipe		
			silkgeoip=${silkgeoip//|/$""}

			# Add the results to the report
			echo "$silkgeoip" >&4

			# Add closing table particulars
			echo "$tableclose" >&4
		else
			badnews "Did you remember to install the GeoIP database?" "$LINENO" "$silkgeoip"				
		fi
	else
		badnews "SiLK or this script" "$LINENO" "$silkgeoip"				
	fi
else
	echo "<center>" >&4
	echo "Skipping SiLK processing!" >&4
fi

# Add HTML closing DIV particulars
echo "$divclose" >&4

# Add ending HTML particulars
echo "</body></html>" >&4

# Close report file
exec 4>&-

# Open the report in web browser for reading
#open $areport                  # mac
firefox "$whereami/$areport" &	# open the report in the background so the script can end
