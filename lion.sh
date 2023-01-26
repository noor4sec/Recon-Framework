#! /bin/bash 
target=$1

echo "
 _____ _          _     _             ____                      
|_   _| |__   ___| |   (_) ___  _ __ |  _ \ ___  ___ ___  _ __  
  | | | '_ \ / _ \ |   | |/ _ \| '_ \| |_) / _ \/ __/ _ \| '_ \ 
  | | | | | |  __/ |___| | (_) | | | |  _ <  __/ (_| (_) | | | |
  |_| |_| |_|\___|_____|_|\___/|_| |_|_| \_\___|\___\___/|_| |_|"
echo "        @Abbas Cyber Security"

if [ ! -d "$target" ]; then
      mkdir $target
fi
if [ ! -d "$target/recon" ]; then
      mkdir $target/recon
fi

if [ ! -d "$target/params-vuln" ]; then
          mkdir $target/params_vuln
fi

if [ ! -d "$target/subs-vuln" ]; then
          mkdir $target/subs_vuln
fi

if [ ! -d "$target/subs-vuln/false-positive" ]; then
          mkdir $target/subs_vuln/false_positive
fi

if [ ! -d "$target/params-vuln/false-positive" ]; then
          mkdir $target/params-vuln/false-positive
fi

if [ ! -d "$target/recon/EyeWitness" ]; then
      mkdir $target/recon/EyeWitness
fi
#---------------------------------------------------------------------------------
#-----------------------------Finding SubDomains----------------------------------
#----------------------------------------------------------------------------------
echo "[+]Enumurating SubDomains Using Amass..." 
amass enum -d $target >> $target/recon/amass.txt
cat $target/recon/amass.txt | grep $target >> $target/recon/final.txt
rm $target/recon/amass.txt

echo "[+]Enumurating SubDomains Using Assetfinder..." 
assetfinder $target >> $target/recon/assetfinder.txt
cat $target/recon/assetfinder.txt | grep $target >> $target/recon/final.txt
rm $target/recon/assetfinder.txt

echo "[+]Enumurating SubDomains Using SubFinder..."
subfinder -d $target -o $target/recon/subfinder.txt
cat $target/recon/subfinder.txt | grep $target >> $target/recon/final.txt
rm $target/recon/subfinder.txt

echo "[+]Enumurating SubDomains Using Findomain..." 
findomain -t $target -q >> $url/recon/findomain.txt
cat $target/recon/findomain.txt | grep $target >> $target/recon/final.txt
rm $target/recon/findomain.txt

echo "[+]Enumurating SubDomains Using Sublist3r..."
python3 /opt/Sublist3r/sublist3r.py -d $target -o $1/recon/sublist3r.txt
cat $target/recon/sublist3r.txt | grep $target >> $target/recon/final.txt
rm $1/recon/sublist3r.txt 

echo "[+]Filtering Repeated Domains........." 
cat $target/recon/final.txt | sort -u | tee $target/recon/final_subs.txt 
rm $target/recon/final.txt 

echo "[+]Total Unique SubDomains" 
cat $target/recon/final_subs.txt | wc -l
#--------------------------------------------------------------------------------------------------
#-----------------------------------Filtering Live SubDomains--------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Removing Dead Domains Using httpx....." 
cat $target/recon/final_subs.txt | httpx --silent  >> $target/recon/live_check.txt

echo "[+]Removing Dead Domains Using httprobe....." 
cat $target/recon/final_subs.txt | httprobe >> $target/recon/live_check.txt

echo "[+]Analyzing Both httpx & httprobe....."
cat $target/recon/live_check.txt | sed 's/https\?:\/\///' | sort -u | tee $target/recon/live_subs.txt 
rm $target/recon/live_check.txt

echo "[+]Total Unique Live SubDomains....."
cat $target/recon/live_subs.txt | wc -l






