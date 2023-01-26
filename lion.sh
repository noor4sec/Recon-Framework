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
          mkdir $target/params-vuln
fi

if [ ! -d "$target/subs-vuln" ]; then
          mkdir $target/subs-vuln
fi

if [ ! -d "$target/recon/false-positive" ]; then
          mkdir $target/recon/false-positive
fi

if [ ! -d "$target/subs-vuln/false-positive" ]; then
          mkdir $target/subs_vuln/false-positive
fi

if [ ! -d "$target/params-vuln/false-positive" ]; then
          mkdir $target/params-vuln/false-positive
fi

if [ ! -d "$target/recon/EyeWitness" ]; then
      mkdir $target/recon/EyeWitness
fi

echo 
" ____  _             _    __        ___ _   _       ____                      
/ ___|| |_ __ _ _ __| |_  \ \      / (_) |_| |__   |  _ \ ___  ___ ___  _ __  
\___ \| __/ _` | '__| __|  \ \ /\ / /| | __| '_ \  | |_) / _ \/ __/ _ \| '_ \ 
 ___) | || (_| | |  | |_    \ V  V / | | |_| | | | |  _ <  __/ (_| (_) | | | |
|____/ \__\__,_|_|   \__|    \_/\_/  |_|\__|_| |_| |_| \_\___|\___\___/|_| |_|"

echo "Finding SubDomains,Parameters,Screenshoting,OperatingSystem,Servers,ServicesRunning,WAFs,OpenPorts,Headers
BreachedData,WhoIs etc.,"

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
findomain -t $target -q >> $target/recon/findomain.txt
cat $target/recon/findomain.txt | grep $target >> $target/recon/final.txt
rm $target/recon/findomain.txt

echo "[+]Enumurating SubDomains Using Sublist3r..."
python3 /opt/Sublist3r/sublist3r.py -d $target -o $1/recon/sublist3r.txt
cat $target/recon/sublist3r.txt | grep $target >> $target/recon/final.txt
rm $1/recon/sublist3r.txt 

echo "[+]BruteForcing With ffuf..."

echo "[+]BruteForcing With projectsiscovery"

echo "[+]Filtering Repeated Domains........." 
cat $target/recon/final.txt | sort -u | tee $target/recon/final-subs.txt 
rm $target/recon/final.txt 

echo "[+]Total Unique SubDomains" 
cat $target/recon/final-subs.txt | wc -l
#--------------------------------------------------------------------------------------------------
#-----------------------------------Filtering Live SubDomains--------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Removing Dead Domains Using httpx....." 
cat $target/recon/final-subs.txt | httpx --silent  >> $target/recon/live_check.txt

echo "[+]Removing Dead Domains Using httprobe....." 
cat $target/recon/final-subs.txt | httprobe >> $target/recon/live_check.txt

echo "[+]Analyzing Both httpx & httprobe....."
cat $target/recon/live_check.txt | sed 's/https\?:\/\///' | sort -u | tee $target/recon/live-subs.txt 
cat $target/recon/live_check.txt | sort -u | tee $target/recon/false-positive/https-subs.txt
rm $target/recon/live_check.txt

echo "[+]Total Unique Live SubDomains....."
cat $target/recon/live-subs.txt | wc -l

#--------------------------------------------------------------------------------------------------
#----------------------------------------Enumurating Urls-----------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Enumurating Params From Paramspider...." 
python3 /opt/Paramspider/paramspider.py --level high -d $target -p noor -o $1/recon/urls.txt
echo "[+]Enumurating Params From Waybackurls...." 
cat $1/recon/live-subs.txt | waybackurls | grep = | qsreplace lion >> $1/recon/urls.txt
echo "[+]Enumurating Params From gau Tool...." 
gau --subs  $target | grep = | qsreplace lion >> $target/recon/urls.txt 
echo "[+]Enumurating Params From gauPlus Tool...." 
cat $target/recon/live-subs.txt | gauplus | grep = | qsreplace lion >> $1/recon/urls.txt
echo "[+]Enumurating Params Using Katana..."
katana -u $target/recon/live-subs.txt | grep = | qsreplace noor >> $target/recon/urls.txt


echo "[+]Filtering Dups..." 
cat $1/recon/urls.txt | sort -u | tee $1/recon/final-params.txt 
rm $target/recon/urls.txt

echo "[+]Total Unique Params Found..." 
cat $target/recon/final-params.txt | wc -l
echo 
" _____              _               ____                               
|  ___|   _ _______(_)_ __   __ _  |  _ \ __ _ _ __ __ _ _ __ ___  ___ 
| |_ | | | |_  /_  / | '_ \ / _` | | |_) / _` | '__/ _` | '_ ` _ \/ __|
|  _|| |_| |/ / / /| | | | | (_| | |  __/ (_| | | | (_| | | | | | \__ \
|_|   \__,_/___/___|_|_| |_|\__, | |_|   \__,_|_|  \__,_|_| |_| |_|___/
                            |___/                                      
Testing For HTML,XSS,Template,Command,CRLF,SQL Injections And LFI,SSRF,OpenRedirects etc.,
"
#--------------------------------------------------------------------------------------------------
#-------------------------------Fuzzing For HTML Injection-----------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Fuzzing For HTML Injection..." 
cat $target/recon/final-params.txt | qsreplace '"><u>hyper</u>' | tee $target/recon/temp.txt && cat $target/recon/temp.txt | while read host do ; do curl --silent --path-as-is --insecure "$host" | grep -qs "><u>hyper</u>" && echo "$host "; done > $target/params-vuln/htmli.txt
#--------------------------------------------------------------------------------------------------
#-------------------------------Fuzzing For Open Redirects-----------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Fuzzing For Openredirects..." 
cat $target/recon/final-params.txt | qsreplace 'https://evil.com' | while read host do ; do curl -s -L $host -I | grep "https://evil.com" && echo "$host" ; done >> $target/params-vuln/open-redirects.txt
#--------------------------------------------------------------------------------------------------
#-------------------------------Checking For SQL Injection-----------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Testing For SQL Injection...." 
cat $target/recon/final-params.txt | python3 /opt/Sqlmap/sqlmap.py --level 2 --risk 2
echo 
" _____              _               ____                        _           
|  ___|   _ _______(_)_ __   __ _  |  _ \  ___  _ __ ___   __ _(_)_ __  ___ 
| |_ | | | |_  /_  / | '_ \ / _` | | | | |/ _ \| '_ ` _ \ / _` | | '_ \/ __|
|  _|| |_| |/ / / /| | | | | (_| | | |_| | (_) | | | | | | (_| | | | | \__ \
|_|   \__,_/___/___|_|_| |_|\__, | |____/ \___/|_| |_| |_|\__,_|_|_| |_|___/
                            |___/                                           
Fuzzing For SubDomainTakeOvers,BrokenLinks,ClickJacking,CRLF Injection,                             
"
#--------------------------------------------------------------------------------------------------
#-------------------------------Fuzzing Domains With Nuclei-----------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Fuzzing Domains With Nuclei..."
cat $url/recon/live_subs.txt | nuclei -t /root/nuclei-templates/ -s critical,high,medium,low >> $1/nuclei.txt




