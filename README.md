## 2025 stats are in
First full year, 365 days, of running. All logs have been compiled and another top stats file has been created ([View here](https://github.com/Cactus356/honeypot-project/blob/main/logs/2025/yearly-stats.txt)). Pretty much all the same lessons as in the 2024 review. Be smart, stay safe.


## 2024 stats are in
I've compiled all the logs from March to December of 2024 ([View here](https://github.com/Cactus356/honeypot-project/blob/main/logs/2024/yearly-stats.txt)). This has been my first "year" running the honeypot. It's been a fun project, changing scripts, VPN configs, not paying attention and having it break when I switch ISP's and having to manually run a bunch of sorting scripts. The usual.

Most of these stats you could have probbaly guessed, but it's still good to reaffirm security measures. Right off the bat:
- If you can block by GeoIP - Block China. 45% of my over 3 million SSH login attempts were from Chinese IP addresses. By blocking one country, we've eliminated almost half of the threats.
- Disable the root account from logging in via SSH. 64% of my over 3 million SSH login attempts tried using the root account.
- Passwords. 123456 came in at number one, and it's because it works. Do better. Four words from the EFF large list is over 3.5 quadrillion combinations. Eight random characters isn't even half that and it's harder to remember.

Not everyone has a firewall with GeoIP blocking, but account names/restrictions and passwords are ideas that are so unbelievably simple. Disable root and use 4 words instead of 1qaz@WSX. Just do it.

Thanks for reading.


# Let's Make A Honeypot
This is going to serve as a blog/documentation/notes/instructions and whatever else related to my latest efforts getting a honeypot up and running. I also plan on sharing statistics here like usernames, passwords, attacking IPs, and more. Current thought is to do that monthly and then at the end of the year or maybe every 6 months, provide log data of all the attacks.

This is a project I've had on my mind for a few reasons. First of all, I think it'd just be a fun project - This is pretty much how my everything else in my homelab started, so why not add this to the list. I'm interested to see where most attacks come from and what credentials they try. I also plan on using the IPs and GeoIP data to add to my existing firewall blocklists.

So what do we need? At base level, an SSH honeypot, some form of logging, and a VPS to run it on. This first honeypot is going to be publicly available, so I really don't want something like that running in my home Proxmox server.

The first honeypot I tried was Cowrie (https://github.com/cowrie/cowrie) which handled both SSH and logging. I got Cowrie up and running, but it was the logging part I couldn't get worked out, mostly because I don't know what I'm doing. I got an ELK stack set up until the Logstash part, which for the life of me I could not get to communicate with Elasticsearch. Time to find a new honeypot.

I found Beelzebub (https://github.com/mariocandela/beelzebub) and went for attempt two. As a plus, in addition to SSH, Beelzebub also includes an HTTP and TCP honeypot. I notice they do have a logging option "Prometheus openmetrics integration" but after my poor ELK attempt, I figure the low tech solution of a text file will work for now. So let's get the show on the road!

### VPS Setup
Login as root, create a new user account, install sudo and add the new user to the sudo group. Password change for both the root and user account to something very secure since this machine is designed to be attacked. Timezone set to UTC since that's how the Beelzebub logs are timestamped. Change the default SSH port to use during setup - Using 22 will obviously interfere with the honeypot and we're going to disable the real SSH later anyway, so let's just make it something different for setup. Lastly a simple update && upgrade to make sure we're all set there.

### Beelzebub install and configuration
Beelzebub can be installed using Docker or the Go compiler, I'll be using Go which I need to set up - https://www.linuxcapable.com/how-to-install-golang-go-on-debian-linux/
```
mkdir go && cd go/
wget https://golang.org/dl/go1.20.2.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.20.2.linux-amd64.tar.gz
echo "export PATH=/usr/local/go/bin:${PATH}" | sudo tee -a $HOME/.profile
source $HOME/.profile
go version
```

I can now download and install Beelzebub, instructions are on their GitHub or below.
```
git clone https://github.com/mariocandela/beelzebub.git
cd beelzebub
go mod download
go build
```

Now to configure a few things. I want to specify a log folder, which we do in beelzebub/configurations/beelzebub.yaml. I want to edit the ssh-22.yaml to not accept any passwords. By default, you can allow false logins and log the commands the attackers are using, but I only want to collect the attack attempt data (IP, country, username, password). So for me, under passwordRegex remove the defaults and add a random string that no bruteforce will ever guess. I also remove the ssh-2222.yaml because I don't plan on using the ChatGPT function (again, only want attack attempt data). I'm going to be running this as a non-privileged user, so I need to make sure it can bind to certain ports without needing to be root. Lastly we're going to create and enable a beelzebub.service to run at boot. All of this below:
```
mkdir -p logs-beelzebub/daily-backup
nano beelzebub/configurations/beelzebub.yaml
nano beelzebub/configurations/services/ssh-22.yaml # Change the accepted passwords
mv beelzebub/configurations/services/ssh-2222.yaml beelzebub/configurations/services/ssh-2222.yaml.bak # Disables this SSH
sudo setcap cap_net_bind_service+ep /path/to/beelzebub # Allows non-root to bind ports without needing sudo
sudo nano /etc/systemd/system/beelzebub.service
```
```
[Unit]
Description= Beelzebub Honeypot

[Service]
User=non-root-user-here
Group=non-root-user-here
WorkingDirectory=/home/non-root-user-here/beelzebub
ExecStart=/home/non-root-user-here/beelzebub/beelzebub

[Install]
WantedBy=multi-user.target
```
```
sudo systemctl enable beelzebub.service
```
Now as far as running a honeypot goes, it's done. If your VPS has something like VNC or another remote solution besides SSH, use that to disable the real SSH service. We don't want a real point of attack and also multiple SSH ports would probably give away a honeypot.
```
sudo systemctl disable sshd
```

### Logging
As I mentioned earlier, I need to get some form of logging going beyond the base level Beelzebub puts out into a never ending file. ELK was out of the question, and while I looked at things like Grafana, I decided to just use the text file it currently spit out and filter from there. With that, I need to solve a couple of problems. I plan on running all the IPs through MaxMind to get Geolocation, and since I don't really want to wait and process a month of logs with potentially outdated GeoIP data, that means daily log rotation. As far as I could tell, Beelzebub just continuously writes to a single log file, so I need a script, which we'll call `rotate.sh` to do a couple things. At midnight, copy the current log and save it as a new file with the date in the name. Then copy a blank log over the current to start over for the day.
```
#! /bin/bash
DATE=$(date -d "1 day ago" +%m-%d-%Y) # Get yesterdays date since this runs at midnight the next day
sleep 15
cp /home/non-root-user-here/logs-beelzebub/current /home/non-root-user-here/logs-beelzebub/daily-backup/$DATE-beelzebub # Copies the current (prior) day into a datestamped file
cp /home/non-root-user-here/logs-beelzebub/blank /home/non-root-user-here/logs-beelzebub/current # Overwrites the current log file to start fresh
```

Cool, now daily logs are being produced. I need to get the logs off the VPS and on to my dedicated logging server, both for storage and to run through MaxMind because I'm not going to run that on the VPS. I thought of a couple options like Syncthing, Wormhole, and ended up using something that was new to me - SFTP. SFTP commands can be put into a bash script, so I can set up a Cron job to run said script at midnight, rotating the logs and sending them to my logging server.
```
#! /bin/bash
DATE=$(date -d "1 day ago" +%m-%d-%Y) # Get yesterdays date since this runs at midnight the next day
sleep 15
cp /home/non-root-user-here/logs-beelzebub/current /home/non-root-user-here/logs-beelzebub/daily-backup/$DATE-beelzebub # Copies the current (prior) day into a datestamped file
cp /home/non-root-user-here/logs-beelzebub/blank /home/non-root-user-here/logs-beelzebub/current # Overwrites the current log file to start fresh
sleep 180
sftp -i /home/non-root-user-here/.ssh/id_ed25519 sftp@10.1.1.12 << DELIMIT
put /home/non-root-user-here/logs-beelzebub/daily-backup/$DATE-beelzebub
bye
DELIMIT
```
```
sudo nano /etc/crontab
00 00 * * * root /home/non-root-user-here/rotate.sh
sudo service cron reload
```
Make sure to set the appropriate ownership and permissions since Cron will run our rotate script daily as root
```
sudo chown root:root rotate.sh
sudo chmod 744 rotate.sh
```

So if logs are going to come to my home network over SFTP, I need to allow the VPS in while still leaving my home network secure. I decided to create a new Wireguard connection and put only this VPS on it. I already use Wireguard in OPNsense for all my mobile devices to connect home, so this was just adding another instance. I created the following firewall rules: Allow access to the logging server on port 22 at the scheduled time of the above Cron job, deny everything else. On the logging server side, I created a chroot jail for the sftp user. So worst case, if the VPS is compromised, the attacker has a 30 minute window to SFTP into a single folder on my logging server. That's good enough for me.

### Logging Server Setup
Recap of where we're at. Beelzebub is up and running on the VPS, continuously logging all attacks to a file. We made a script that runs daily at midnight to take that file, copy it, add the date to the name, then overwrite the original file to start fresh for the new day. The script then takes the dated file and sends it to my local logging server via SFTP, which it's connected to via my Wireguard VPN.

Now on the logging server, we're going to start cleaning up this log and getting into the final lists that we want. Let's make a folder for all Beelzebub logs, and subfolders for full daily backups and monthly logs.
```
mkdir -p logs-beelzebub/backup-daily-full
mkdir -p logs-beelzebub/monthly-logs
```
Within the monthly logs folder, we'll create a folder for each month, like `03-2024`, `04-2024`, `05-2024`, etc.

Let's create `daily-log-import.sh`, which will move the daily log out of the chroot folder and into the daily backup folder, then create a copy in the appropriate month that we can work from.
```
#! /bin/bash
DATE=$(date +%m-%d-%Y)
MONTH=$(date +%m-%Y)

# Moves imported daily log to the backup dir
mv /sftp/sftp/$DATE-beelzebub /home/non-root-user/logs-beelzebub/backup-daily-full/

# Copies the daily log to work from
cp /home/non-root-user/logs-beelzebub/backup-daily-full/$DATE-beelzebub /home/non-root-user/logs-beelzebub/monthly-logs/$MONTH/
```

Now it's time to sort this log and break it down into the stats I mentioned at the beginning. Some of the following scripts will use GeoIP, so we'll get that set up. Create an account with Maxmind if you haven't already. Go to 'Manage license keys" and generate a new one for the logging server. Install their GeoIPUpdate program (https://dev.maxmind.com/geoip/updating-databases, https://github.com/maxmind/geoipupdate), which we'll use to download their databases later in our scripts. You could make it a Cron job instead of including it in one of the following scripts, but it's up to you. We're then going to use the mmdbinspect program (https://github.com/maxmind/mmdbinspect) to actually do the geolocating. So get those installed and let's continue with the scripts.

By default, every line of the log looks like this, filled out to a various extent depending on the attack
```
{"event":"DateTime":"","RemoteAddr":"","Protocol":"","Command":"","CommandOutput":"","Status":"","Msg":"","ID":"","Environ":"","User":"","Password":"","Client":"","Headers":"","Cookies":"","UserAgent":"","HostHTTPRequest":"","Body":"","HTTPMethod":"","RequestURI":"","Description":""},"level":"","msg":"","status":""}
```

I want to split the log into three lists - SSH, TCP, and HTTP attacks - And we'll use a unique script for each attack. Each of these will contain the date, attacking IP, country, and protocol. Each list will also contain certain stats only applicable to it's protocol. SSH - Username, password, and SSH client. TCP - Command. HTTP - RequestURI. So I need to remove all other stats (Headers, body, etc), clean up special characters, and remove the first part of the stat (So instead of "Password":"123456", it just shows "123456"). I also need to get just a list of IPs that we can feed to mmdbinspect, then we need to clean up that output because the only info we want from MaxMind is the country. We'll insert that country list back into the list that has the rest of the stats. The code is definitely a mess and could probably be written better, but it was my first time using tools like `sed` to try and filter these lists. The scripts for SSH, TCP, and HTTP are below.
```
# ssh-filter-and-geoip.sh
#!/bin/bash
DATE=$(date +%m-%d-%Y)
MONTH=$(date +%m-%Y)

cd /home/user/logs-beelzebub/monthly-logs/$MONTH/  # Enter logs dir

geoipupdate  # Update GeoIP Database

grep SSH $DATE-beelzebub > full-sshonly.txt  # Get only the SSH logs

cut -d, -f1,2,3,10,11,12 full-sshonly.txt > shortened-sshonly.txt && rm full-sshonly.txt  # Pulls only the fields I want

sed -e 's/{"event":{"DateTime"://g' -e 's/"RemoteAddr"://g' -e 's/"Protocol"://g' -e 's/"User"://g' -e 's/"Password"://g' \
-e 's/"Client"://g' shortened-sshonly.txt > clean-sshonly.txt && rm shortened-sshonly.txt  # Cleans it up, leaves date / source IP / protocol / username / password / client

cut -d, -f1 clean-sshonly.txt > date-sshonly.txt && cut -d, -f2 clean-sshonly.txt > ip-sshonly.txt && \
cut -d, -f3,4,5,6 clean-sshonly.txt > remaining-sshonly.txt && rm clean-sshonly.txt  # Creates 3 lists: Date, IP, and protocol / username / password / client

sed -e 's/T.*//' -e 's/.*/&"/' date-sshonly.txt > date-notime-sshonly.txt && rm date-sshonly.txt  # Removes time from the datestamp, leaving only yyyy-mm-dd

sed -e 's/"//g' -e 's/:.*//' ip-sshonly.txt > import-maxmind.txt && rm ip-sshonly.txt  # Cleans IP list into straight IPs for MaxMind

cat import-maxmind.txt | sudo xargs /home/user/mmdbinspect_0.2.0_linux_amd64/mmdbinspect \
-db /usr/share/GeoIP/GeoLite2-City.mmdb > maxmind-results.txt && rm import-maxmind.txt  # Runs MaxMind GeoIP check

grep "Lookup" maxmind-results.txt > ip-maxmind-results.txt  # Display MaxMind searched IP

sed -e 's/        "Lookup": //g' ip-maxmind-results.txt > ip-maxmind-results.tmp && \
mv ip-maxmind-results.tmp ip-maxmind-results.txt  # Clean searched IP list

jq -r '.[].Records[].Record.country.names.en' maxmind-results.txt > country-maxmind-results.txt  # Display MaxMind searched country

sed 's/.*/"&"/' country-maxmind-results.txt > country-maxmind-results.tmp && \
mv country-maxmind-results.tmp country-maxmind-results.txt  # Add quotes to searched country list

paste -d "," date-notime-sshonly.txt ip-maxmind-results.txt country-maxmind-results.txt \
remaining-sshonly.txt > SSH-$DATE-beelzebub-complete.txt  # Combine everything

rm country-maxmind-results.txt && rm ip-maxmind-results.txt && rm remaining-sshonly.txt && \
rm date-notime-sshonly.txt && rm maxmind-results.txt  # Delete temp files
```
```
# tcp-filter-and-geoip.sh
#!/bin/bash
DATE=$(date +%m-%d-%Y)  
MONTH=$(date +%m-%Y)

cd /home/user/logs-beelzebub/monthly-logs/$MONTH/  # Enter logs dir 

# geoipupdate  # Update GeoIP Database , currently disables since the SSH script does it

grep TCP $DATE-beelzebub > full-tcp-only.txt && grep '\\' full-tcp-only.txt > full-tcp-commands-only.txt && \  
rm full-tcp-only.txt  # Get only the TCP logs  

cut -d, -f1,2,3,4 full-tcp-commands-only.txt > shortened-tcp-commands-only.txt && rm full-tcp-commands-only.txt  # Pulls only the fields I want  

sed -e 's/{"event":{"DateTime"://g' -e 's/"RemoteAddr"://g' -e 's/"Protocol"://g' -e 's/"Command"://g' \  
shortened-tcp-commands-only.txt > clean-tcp-commands-only.txt && rm shortened-tcp-commands-only.txt  # Cleans it up, leaves date / source IP / protocol / username / password / client  

cut -d, -f1 clean-tcp-commands-only.txt > date-tcp-commands-only.txt && cut -d, -f2 clean-tcp-commands-only.txt > \  
ip-tcp-commands-only.txt && cut -d, -f3,4 clean-tcp-commands-only.txt > remaining-tcp-commands-only.txt && \  
rm clean-tcp-commands-only.txt  # Creates 3 lists: Date, IP, and protocol / command  


sed -e 's/T.*//' -e 's/.*/&"/' date-tcp-commands-only.txt > date-notime-tcp-commands-only.txt && rm date-tcp-commands-only.txt  # Removes time from the datestamp, leaving only yyyy-mm-dd  

sed -e 's/"//g' -e 's/:.*//' ip-tcp-commands-only.txt > import-maxmind-tcp.txt && rm ip-tcp-commands-only.txt  # Cleans IP list into straight IPs for MaxMind  

cat import-maxmind-tcp.txt | sudo xargs /home/user/mmdbinspect_0.2.0_linux_amd64/mmdbinspect \  
-db /usr/share/GeoIP/GeoLite2-City.mmdb > maxmind-results-tcp.txt && rm import-maxmind-tcp.txt  # Runs MaxMind GeoIP check,  

grep "Lookup" maxmind-results-tcp.txt > ip-maxmind-results-tcp.txt  # Display MaxMind searched IP  

sed -e 's/ "Lookup": //g' ip-maxmind-results-tcp.txt > ip-maxmind-results-tcp.tmp && \  
mv ip-maxmind-results-tcp.tmp ip-maxmind-results-tcp.txt  # Clean searched IP list  

jq -r '.[].Records[].Record.country.names.en' maxmind-results-tcp.txt > country-maxmind-results-tcp.txt  # Display MaxMind searched country  

sed 's/.*/"&"/' country-maxmind-results-tcp.txt > country-maxmind-results-tcp.tmp && \  
mv country-maxmind-results-tcp.tmp country-maxmind-results-tcp.txt  # Add quotes to searched country list  

paste -d "," date-notime-tcp-commands-only.txt ip-maxmind-results-tcp.txt country-maxmind-results-tcp.txt \  
remaining-tcp-commands-only.txt > TCP-$DATE-beelzebub-complete.txt  # Combine everything  
```
```
# http-filter-and-geoip-step2.sh
#! /bin/bash  
DATE=$(date +%m-%d-%Y)  
MONTH=$(date +%m-%Y)  
  
cd /home/user/logs-beelzebub/monthly-logs/$MONTH/  # Enter logs dir  

# geoipupdate  # Update GeoIP Database , currently disables since the SSH script does it

grep '"Protocol":"HTTP"' $DATE-beelzebub > full-http-only.txt && grep -wv '"RequestURI":"/"' full-http-only.txt \  
> full-http-commands-only.txt && rm full-http-only.txt  # Get only the SSH logs  

cut -d, -f1,2,3 full-http-commands-only.txt > date-ip-http-http-only.txt && \  
rev full-http-commands-only.txt | cut '-d,' -f 5 | rev > uri-http-only.txt && \  
paste -d "," date-ip-http-http-only.txt uri-http-only.txt > shortened-http-only.txt && \  
rm full-http-commands-only.txt date-ip-http-http-only.txt uri-http-only.txt  # Pulls only the fields I want  

sed -e 's/{"event":{"DateTime"://g' -e 's/"RemoteAddr"://g' -e 's/"Protocol"://g' -e 's/"RequestURI"://g' shortened-http-only.txt \  
> clean-http-only.txt && rm shortened-http-only.txt  # Cleans it up, leaves date / source IP / protocol / username / password / client  

cut -d, -f1 clean-http-only.txt > date-http-only.txt && cut -d, -f2 clean-http-only.txt > ip-http-only.txt && \  
cut -d, -f3,4 clean-http-only.txt > remaining-http-only.txt && rm clean-http-only.txt  # Creates 3 lists: Date, IP, and protocol / RequestURI  

sed -e 's/T.*//' -e 's/.*/&"/' date-http-only.txt > date-notime-http-only.txt && rm date-http-only.txt  # Removes time from the datestamp, leaving only yyyy-mm-dd  

sed -e 's/"//g' -e 's/:.*//' ip-http-only.txt > import-maxmind-http.txt && rm ip-http-only.txt  # Cleans IP list into straight IPs for MaxMind  

cat import-maxmind-http.txt | sudo xargs /home/user/mmdbinspect_0.2.0_linux_amd64/mmdbinspect \  
-db /usr/share/GeoIP/GeoLite2-City.mmdb > maxmind-results-http.txt && rm import-maxmind-http.txt  # Runs MaxMind GeoIP check

grep "Lookup" maxmind-results-http.txt > ip-maxmind-results-http.txt  # Display MaxMind searched IP  

sed -e 's/ "Lookup": //g' ip-maxmind-results-http.txt > ip-maxmind-results-http.tmp && \  
mv ip-maxmind-results-http.tmp ip-maxmind-results-http.txt  # Clean searched IP list  

jq -r '.[].Records[].Record.country.names.en' maxmind-results-http.txt > country-maxmind-results-http.txt  # Display MaxMind searched country  

sed 's/.*/"&"/' country-maxmind-results-http.txt > country-maxmind-results-http.tmp && \  
mv country-maxmind-results-http.tmp country-maxmind-results-http.txt  # Add quotes to searched country list  

paste -d "," date-notime-http-only.txt ip-maxmind-results-http.txt country-maxmind-results-http.txt \  
remaining-http-only.txt > HTTP-$DATE-beelzebub-complete.txt  # Combine everything  
```
Here is an example output from a completed daily SSH log:
```
"2024-04-24","211.252.xxx.xx",,"SSH","root","test","SSH-2.0-libssh2_1.9.0"
"2024-04-24","211.252.xxx.xx",,"SSH","root","toor","SSH-2.0-libssh2_1.9.0"
"2024-04-24","211.252.xxx.xx",,"SSH","root","qwerty","SSH-2.0-libssh2_1.9.0"
```
So now within each monthly folder (ie 04-2024), there will be 4 log files for each day - The full unfiltered, SSH, TCP, and HTTP. We'll combine the daily lists for SSH and TCP into their own all-days list for that month. I'm choosing to omit HTTP because some of the "attacks" are just content scans and I don't feel like filtering those. The SSH list is obvious attacks and the TCP list only contains those in which a command was used, so those should be positive attacks as well. We'll use this all-days list to get both our monthly stats for SSH and TCP, and then build our master list of attacking IPs from both the SSH and TCP list. Again, code is probably a mess but it works.
```
# ssh-monthly-combine-and-report.sh
#! /bin/bash  
MONTHNUM=$(date -d "1 month ago" +'%m-%Y')  
MONTHNAME=$(date -d "1 month ago" +'%B')

cd /home/user/logs-beelzebub/monthly-logs/$MONTHNUM  # Enter logs dir  
  
cat SSH*.txt | sed -e 's/"//g' > SSH-$MONTHNAME-alldays.txt  # Combine daily files into one monthly file and remove quotes

# Variables for all stats. For cut, list goes: Date, IP, Country, SSH, Username, Password, Client  
ATKCNT=$(wc -l SSH-$MONTHNAME-alldays.txt | cut '-d ' -f1)  
UNIQUEIPS=$(cut -d, -f2 SSH-$MONTHNAME-alldays.txt | sort | uniq -c | wc -l)  
TOPDATES=$(cut -d, -f1 SSH-$MONTHNAME-alldays.txt | sort | uniq -c | sort -nr | head -10 | awk '{$1=$1};1' | awk '{print $2,$1}')  
TOPIPS=$(cut -d, -f2 SSH-$MONTHNAME-alldays.txt | sort | uniq -c | sort -nr | head -100 | awk '{$1=$1};1' | awk '{print $2,$1}')  
TOPCOUNTRY=$(cut -d, -f3 SSH-$MONTHNAME-alldays.txt | sort | uniq -c | sort -nr | head -10 | awk '{$1=$1};1' | awk '{print $2,$3,$1}')  
TOPUSER=$(cut -d, -f5 SSH-$MONTHNAME-alldays.txt | sort | uniq -c | sort -nr | head -10 | awk '{$1=$1};1' | awk '{print $2,$1}')  
TOPPASS=$(cut -d, -f6 SSH-$MONTHNAME-alldays.txt | sort | uniq -c | sort -nr | head -50 | awk '{$1=$1};1' | awk '{print $2,$1}')  
TOPCLIENT=$(cut -d, -f7 SSH-$MONTHNAME-alldays.txt | sort | uniq -c | sort -nr | head -5 | awk '{$1=$1};1' | awk '{print $2,$1}')

# Push stats to the final log for the month  
echo -e "\nTotal SSH attacks: $ATKCNT\n\n------------------------------" > SSH-$MONTHNAME-stats.txt  
echo -e "\nUnique attacking IPs: $UNIQUEIPS\n\n------------------------------" >> SSH-$MONTHNAME-stats.txt  
echo -e "\nTop 10 attack dates: \n$TOPDATES\n\n------------------------------" >> SSH-$MONTHNAME-stats.txt  
echo -e "\nTop 10 attacking countries: \n$TOPCOUNTRY\n\n------------------------------" >> SSH-$MONTHNAME-stats.txt  
echo -e "\nTop 10 tried usernames: \n$TOPUSER\n\n------------------------------" >> SSH-$MONTHNAME-stats.txt  
echo -e "\nTop 50 tried passwords: \n$TOPPASS\n\n------------------------------" >> SSH-$MONTHNAME-stats.txt  
echo -e "\nTop 100 attacking IPs: \n$TOPIPS\n\n------------------------------" >> SSH-$MONTHNAME-stats.txt  
echo -e "\nTop 5 clients used: \n$TOPCLIENT" >> SSH-$MONTHNAME-stats.txt
```
```
# tcp-monthly-combine-and-report.sh
#! /bin/bash  
MONTHNUM=$(date -d "1 month ago" +'%m-%Y')  
MONTHNAME=$(date -d "1 month ago" +'%B')

cd /home/user/logs-beelzebub/monthly-logs/$MONTHNUM  # Enter logs dir  

cat TCP*.txt | sed -e 's/"//g' > TCP-$MONTHNAME-alldays.txt  # Combine daily files into one monthly file and remove quotes  

# Variables for all stats. For cut, list goes: Date, IP, Country, TCP, Username, Password, Client  
ATKCNT=$(wc -l TCP-$MONTHNAME-alldays.txt | cut '-d ' -f1)  
UNIQUEIPS=$(cut -d, -f2 TCP-$MONTHNAME-alldays.txt | sort | uniq -c | wc -l)  
TOPDATES=$(cut -d, -f1 TCP-$MONTHNAME-alldays.txt | sort | uniq -c | sort -nr | head -10 | awk '{$1=$1};1' | awk '{print $2,$1}')  
TOPIPS=$(cut -d, -f2 TCP-$MONTHNAME-alldays.txt | sort | uniq -c | sort -nr | head -100 | awk '{$1=$1};1' | awk '{print $2,$1}')  
TOPCOUNTRY=$(cut -d, -f3 TCP-$MONTHNAME-alldays.txt | sort | uniq -c | sort -nr | head -10 | awk '{$1=$1};1' | awk '{print $2,$3,$1}')

# Push stats to the final log for the month  
echo -e "\nTotal TCP attacks: $ATKCNT\n\n------------------------------" > TCP-$MONTHNAME-stats.txt  
echo -e "\nUnique attacking IPs: $UNIQUEIPS\n\n------------------------------" >> TCP-$MONTHNAME-stats.txt  
echo -e "\nTop 10 attack dates: \n$TOPDATES\n\n------------------------------" >> TCP-$MONTHNAME-stats.txt  
echo -e "\nTop 10 attacking countries: \n$TOPCOUNTRY\n\n------------------------------" >> TCP-$MONTHNAME-stats.txt  
echo -e "\nTop 100 attacking IPs: \n$TOPIPS\n\n------------------------------" >> TCP-$MONTHNAME-stats.txt
```
Below is an example of the resulting SSH-$Month-stats.txt (trimmed for ease of reading)
```
Total SSH attacks: 100409

------------------------------

Unique attacking IPs: 2476

------------------------------

Top 10 attack dates:
2024-03-22 27872
2024-03-26 16601

------------------------------

Top 10 attacking countries:
China  74610
Brazil  11954

------------------------------

Top 10 tried usernames:
root 91240
admin 1047

------------------------------

Top 50 tried passwords:
123456 687
1234 473

------------------------------

Top 100 attacking IPs:
171.216.85.95 33319

------------------------------

Top 5 clients used:
SSH-2.0-Go 53122
SSH-2.0-PUTTY 32019
```
Now with our `SSH-$Month_alldays.txt` and `TCP-$Month_alldays.txt` created, we can run our final script. This pulls the IP column from both lists and sorts them, removing duplicates, giving us a list of pure IPs that we can feed into our firewall or whatever else.
```
# attacking-ips-SSH-TCP.sh
#! /bin/bash
MONTHNUM=$(date -d "1 month ago" +'%m-%Y')  
MONTHNAME=$(date -d "1 month ago" +'%B')

cd /home/user/logs-beelzebub/monthly-logs/$MONTHNUM  # Enter logs dir  

# Pulls IP field from SSH, TCP, and relevant HTTP attacks  
cut -d, -f2 TCP-$MONTHNAME-alldays.txt >> all-attacking-ips-$MONTHNUM-SSH-TCP.txt  
cut -d, -f2 SSH-$MONTHNAME-alldays.txt >> all-attacking-ips-$MONTHNUM-SSH-TCP.txt

sort all-attacking-ips-$MONTHNUM-SSH-TCP.txt | uniq >> all32.tmp && mv all32.tmp all-attacking-ips-$MONTHNUM-SSH-TCP.txt
```
Now we need to add all of the scripts we created to our Cron.
```
15 20   * * *   root    /home/user/scripts-main/daily-log-import.sh
30 20   * * *   root    /home/user/scripts-main/ssh-filter-and-geoip.sh
40 20   * * *   root    /home/user/scripts-main/tcp-filter-and-geoip.sh
50 20   * * *   root    /home/user/scripts-main/http-filter-and-geoip.sh
#
15 0    1 * *   root    /home/user/scripts-main/ssh-monthly-combine-and-report.sh
30 0    1 * *   root    /home/user/scripts-main/tcp-monthly-combine-and-report.sh
0 1     1 * *   root    /home/user/scripts-main/attacking-ips-SSH-TCP.sh
```
Remember, any script you're running via Cron as root needs to have appropriate perms. I keep all my scripts in a folder, so all I need to do is:
```
sudo chown root:root *.sh
sudo chmod 744 *.sh
```
As you can see, the dailies (log import, SSH/TCP/HTTP filter) are all run during 2000 - This is due to the Beelzebub server being in UTC, while my logging server is in my local timezone. The log is actually for the previous day in UTC, but the logging server thinks it's the current day. You should adjust this if your timezones are set differently, either in the scripts or when Cron runs them.

### Conclusion
Oof, that was a lot of typing, but I think I'm done! I'll upload the attack logs to this repo, which will also include the results from the scripts created above.

Last updated: 04/26/2024
