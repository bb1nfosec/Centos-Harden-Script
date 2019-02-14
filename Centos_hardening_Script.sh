#!/bin/bash

echo "


                                             LLLLLLLLLLL              iiii
                                             L:::::::::L             i::::i
                                             L:::::::::L              iiii
                                             LL:::::::LL
                                               L:::::L              iiiiiinnnn  nnnnnnnn   uuuuuu    uuuuuu xxxxxxx      xxxxxxx
                                               L:::::L              i:::::n:::nn::::::::nn u::::u    u::::u  x:::::x    x:::::x
                                               L:::::L               i::::n::::::::::::::nnu::::u    u::::u   x:::::x  x:::::x
                                               L:::::L               i::::nn:::::::::::::::u::::u    u::::u    x:::::xx:::::x
                                               L:::::L               i::::i n:::::nnnn:::::u::::u    u::::u     x::::::::::x
                                               L:::::L               i::::i n::::n    n::::u::::u    u::::u      x::::::::x
                                               L:::::L               i::::i n::::n    n::::u::::u    u::::u      x::::::::x
                                               L:::::L         LLLLLLi::::i n::::n    n::::u:::::uuuu:::::u     x::::::::::x
                                             LL:::::::LLLLLLLLL:::::i::::::in::::n    n::::u:::::::::::::::uu  x:::::xx:::::x
                                             L::::::::::::::::::::::i::::::in::::n    n::::nu:::::::::::::::u x:::::x  x:::::x
                                             L::::::::::::::::::::::i::::::in::::n    n::::n uu::::::::uu:::ux:::::x    x:::::x
                                             LLLLLLLLLLLLLLLLLLLLLLLiiiiiiiinnnnnn  dddddddd   uuuuuuuu  uuuxxxxxxx      xxxxxxx
               HHHHHHHHH     HHHHHHHHH                                              d::::::d                                     iiii
               H:::::::H     H:::::::H                                              d::::::d                                    i::::i                                    
               H:::::::H     H:::::::H                                              d::::::d                                     iiii
               HH::::::H     H::::::HH                                              d:::::d
                 H:::::H     H:::::H   aaaaaaaaaaaaa rrrrr   rrrrrrrrr      ddddddddd:::::d    eeeeeeeeeeee   nnnn  nnnnnnnn   iiiiiinnnn  nnnnnnnn      ggggggggg   ggggg
                 H:::::H     H:::::H   a::::::::::::ar::::rrr:::::::::r   dd::::::::::::::d  ee::::::::::::ee n:::nn::::::::nn i:::::n:::nn::::::::nn   g:::::::::ggg::::g
                 H::::::HHHHH::::::H   aaaaaaaaa:::::r:::::::::::::::::r d::::::::::::::::d e::::::eeeee:::::en::::::::::::::nn i::::n::::::::::::::nn g:::::::::::::::::g
                 H:::::::::::::::::H            a::::rr::::::rrrrr::::::d:::::::ddddd:::::de::::::e     e:::::nn:::::::::::::::ni::::nn:::::::::::::::g::::::ggggg::::::gg
                 H:::::::::::::::::H     aaaaaaa:::::ar:::::r     r:::::d::::::d    d:::::de:::::::eeeee::::::e n:::::nnnn:::::ni::::i n:::::nnnn:::::g:::::g     g:::::g
                 H::::::HHHHH::::::H   aa::::::::::::ar:::::r     rrrrrrd:::::d     d:::::de:::::::::::::::::e  n::::n    n::::ni::::i n::::n    n::::g:::::g     g:::::g
                 H:::::H     H:::::H  a::::aaaa::::::ar:::::r           d:::::d     d:::::de::::::eeeeeeeeeee   n::::n    n::::ni::::i n::::n    n::::g:::::g     g:::::g
                 H:::::H     H:::::H a::::a    a:::::ar:::::r           d:::::d     d:::::de:::::::e            n::::n    n::::ni::::i n::::n    n::::g::::::g    g:::::g
               HH::::::H     H::::::Ha::::a    a:::::ar:::::r           d::::::ddddd::::::de::::::::e           n::::n    n::::i::::::in::::n    n::::g:::::::ggggg:::::g
               H:::::::H     H:::::::a:::::aaaa::::::ar:::::r            d:::::::::::::::::de::::::::eeeeeeee   n::::n    n::::i::::::in::::n    n::::ng::::::::::::::::g
               H:::::::H     H:::::::Ha::::::::::aa:::r:::::r             d:::::::::ddd::::d ee:::::::::::::e   n::::n    n::::i::::::in::::n    n::::n gg::::::::::::::g
               HHHHHHHHH     HHHHHHHHH aaaaaaaaaa  aaarrrrrrr              ddddddddd   ddddd   eeeeeeeeeeeeee   nnnnnn    nnnnniiiiiiiinnnnnn    nnnnnn   gggggggg::::::g
                                                                                                                                                                  g:::::g
                                                                                                                                                      gggggg      g:::::g
                                                                                                                                                      g:::::gg   gg:::::g
                                                                                                                                                       g::::::ggg:::::::g
                                                                                                                                                        gg:::::::::::::g
                                                                                                                                                          ggg::::::ggg
                                                                                                                                                             gggggg




"













#Connect the system to the network
sudo dhclient

#To update the system
yum -y update
yum -y upgrade
echo "update & upgrade done"

#INSTALL NTP
yum -y install ntp ntpdate
chkconfig ntpd on
ntpdate pool.ntp.org
/etc/init.d/ntpd start
echo "NTP installation Done"

#Configure System AIDE
# Disable prelinking altogether
if grep -q ^PRELINKING /etc/sysconfig/prelink
then
  sed -i 's/PRELINKING.*/PRELINKING=no/g' /etc/sysconfig/prelink
  sed -i 's/PRELINKING.*/PRELINKING=no/g' /etc/sysconfig/prelink
  else
  echo -e "\n# Set PRELINKING=no per security requirements" >> /etc/sysconfig/prelink
  echo "PRELINKING=no" >> /etc/sysconfig/prelink
fi
echo "PRELINKING is set to no"
#Install AIDE
#nstall AIDE - Advanced Intrusion Detection Environment
yum install aide -y && /usr/sbin/aide --init && cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz && /usr/sbin/aide --check && bind ^C stuff ^C
echo "AIDE is installed"

#Configure periodic execution of AIDE, runs every morning at 04:30
echo "05 4 * * * root /usr/sbin/aide --check" >> /etc/crontab
echo "configured periodic execution of AIDE, runs every morning at 04:30"

#Prevent Users Mounting USB Storage
echo "install usb-storage /bin/false" > /etc/modprobe.d/usb-storage.conf
echo "Prevented Users Mounting USB Storage"

#Enable Secure (high quality) Password Policy
#Enable SHA512 instead of using MD5:
authconfig --passalgo=sha512 —update

sed -i 's/difok.*/difok = 3/g' /etc/security/pwquality.conf
sed -i 's/minlen.*/minlen = 9/g' /etc/security/pwquality.conf
sed -i 's/dcredit.*/dcredit = 1/g' /etc/security/pwquality.conf
sed -i 's/ucredit.*/ucredit = 2/g' /etc/security/pwquality.conf
sed -i 's/lcredit.*/lcredit = 1/g' /etc/security/pwquality.conf
sed -i 's/ocredit.*/ocredit = 1/g' /etc/security/pwquality.conf
sed -i 's/minclass.*/minclass = 1/g' /etc/security/pwquality.conf
sed -i 's/maxrepeat.*/maxrepeat = 2/g' /etc/security/pwquality.conf
sed -i 's/maxclassrepeat.*/maxclassrepeat = 2/g' /etc/security/pwquality.conf
sed -i 's/gecoscheck.*/gecoscheck = 1/g' /etc/security/pwquality.conf

#Secure /etc/login.defs Pasword Policy

sed -i 's/PASS_MIN_LEN.*/PASS_MIN_LEN    9/g' /etc/login.defs
sed -i 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS    1/g' /etc/login.defs
sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS    30/g' /etc/login.defs
sed -i 's/PASS_WARN_AGE.*/PASS_WARN_AGE    28/g' /etc/login.defs
echo "secure /etc/login.defs Pasword Policy"
#Set Last Logon/Access Notification
sed -i '/pam_limits.so/a session     required      pam_lastlog.so showfailed' /etc/pam.d/system-auth
echo "configured Last Logon/Access Notification"

#Lock user after N incorrect logins
#in /etc/pam.d/system-auth
if grep -q ^auth        [default=die] /etc/pam.d/system-auth
then
	echo "Already Done"
 else
	sed -i '/auth        sufficient    pam_unix.so/a auth        [default=die] pam_faillock.so authfail deny=3 unlock_time=600 fail_interval=900\nauth        required      pam_faillock.so authsucc deny=3 unlock_time=600 fail_interval=900' /etc/pam.d/system-auth
fi
echo "Locked user after 3 incorrect logins & locks up to 10min"

#/etc/pam.d/password-auth
if grep -q ^auth        [default=die] /etc/pam.d/password-auth
then
	echo "Already Done"
else
	sed -i '/auth        sufficient    pam_unix.so/a auth        [default=die] pam_faillock.so authfail deny=3 unlock_time=600 fail_interval=900\nauth        required      pam_faillock.so authsucc deny=3 unlock_time=600 fail_interval=900' /etc/pam.d/system-auth
fi

echo "Set Deny For Failed Password Attempts"

#Limit Password Reuse
if grep -q ^pam_unix.so existing_options /etc/pam.d/system-auth
then
	echo "Already Done"
  else
	sed -i '/password    sufficient    pam_unix.so/a password    sufficient    pam_unix.so existing_options remember=24' /etc/pam.d/system-auth
fi

echo "limited password Reuse"


#Authentication for Single User Mode
if grep -q ^SINGLE /etc/sysconfig/init
then
	echo "Authentication for Single User Mode"
	sed -i 's/SINGLE.*/SINGLE=/sbin/sulogin/g' /etc/sysconfig/init
  else
	echo "# Set Require Authentication for Single User Mode" >> /etc/sysconfig/init
	echo "SINGLE=/sbin/sulogin" >> /etc/sysconfig/init
fi
echo "Authentication for Single User Mode provided"

#Disable Ctrl-Alt-Del Reboot Activation
echo "exec /usr/bin/logger -p security.info "Control-Alt-Delete pressed"" >> /etc/init/control-alt-delete.conf
if grep logger /etc/init/control-alt-delete.conf
then
	echo "Already Disabled Ctrl-Alt-Del Reboot Activation"

  else
	sed -i '/sbin/d' /etc/init/control-alt-delete.conf
	echo "# Set Require Authentication for Single User Mode" >> /etc/init/control-alt-delete.conf
	echo "exec /usr/bin/logger -p security.info "Control-Alt-Delete pressed"" >> /etc/init/control-alt-delete.conf
  	echo "Disabled Ctrl-Alt-Del Reboot Activation"
fi

#Enable Console Screen Locking
sudo yum -y install screen
echo "Enabled Console Screen Locking"

#Securing root Logins
echo "tty1" > /etc/securetty
chmod 700 /root
echo "Secured root Logins"

#Prune Idle Users
/*
echo "Idle users will be removed after 15 minutes"
echo "readonly TMOUT=900" >> /etc/profile.d/os-security.sh
echo "readonly HISTFILE" >> /etc/profile.d/os-security.sh
chmod +x /etc/profile.d/os-security.sh
echo "Prune Idle Users"
*/

#Securing Cron
echo "Locking down Cron"
touch /etc/cron.allow
chmod 600 /etc/cron.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny
echo "Locking down AT"
touch /etc/at.allow
chmod 600 /etc/at.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/at.deny
echo "Secured Cron"

#Sysctl Security
if grep -q ^net.ipv4.ip_forward /etc/sysctl.conf
then
	sed -i 's/net.ipv4.ip_forward.*/net.ipv4.ip_forward = 0/g' /etc/sysctl.conf
  else
	echo "# ip_forward" >> /etc/sysctl.conf
	echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
fi

if grep -q ^net.ipv4.conf.all.send_redirects /etc/sysctl.conf
then
	sed -i 's/net.ipv4.conf.all.send_redirects.*/net.ipv4.conf.all.send_redirects = 0/g' /etc/sysctl.conf
  else
	echo "# net.ipv4.conf.all.send_redirects" >> /etc/sysctl.conf
	echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
fi

if grep -q ^net.ipv4.conf.default.send_redirects /etc/sysctl.conf
then
	sed -i 's/net.ipv4.conf.default.send_redirects.*/net.ipv4.conf.default.send_redirects = 0/g' /etc/sysctl.conf
  else
	echo "# net.ipv4.conf.default.send_redirects" >> /etc/sysctl.conf
	echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
fi

if grep -q ^net.ipv4.tcp_max_syn_backlog /etc/sysctl.conf
then
	sed -i 's/net.ipv4.tcp_max_syn_backlog.*/net.ipv4.tcp_max_syn_backlog = 1280/g' /etc/sysctl.conf
  else
	echo "# net.ipv4.tcp_max_syn_backlog" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_max_syn_backlog = 1280" >> /etc/sysctl.conf
fi

if grep -q ^net.ipv4.icmp_echo_ignore_broadcasts /etc/sysctl.conf
then
	sed -i 's/net.ipv4.icmp_echo_ignore_broadcasts.*/net.ipv4.icmp_echo_ignore_broadcasts = 1/g' /etc/sysctl.conf
  else
	echo "# net.ipv4.icmp_echo_ignore_broadcasts" >> /etc/sysctl.conf
	echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
fi

if grep -q ^net.ipv4.conf.all.accept_source_route /etc/sysctl.conf
then
	sed -i 's/net.ipv4.conf.all.accept_source_route.*/net.ipv4.conf.all.accept_source_route = 0/g' /etc/sysctl.conf
  else
	echo "# net.ipv4.conf.all.accept_source_route" >> /etc/sysctl.conf
	echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
fi

if grep -q ^net.ipv4.conf.all.accept_redirects /etc/sysctl.conf
then
	sed -i 's/net.ipv4.conf.all.accept_redirects.*/net.ipv4.conf.all.accept_redirects = 0/g' /etc/sysctl.conf
  else
	echo "# net.ipv4.conf.all.accept_redirects" >> /etc/sysctl.conf
	echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
fi

if grep -q ^net.ipv4.conf.all.secure_redirects /etc/sysctl.conf
then
	sed -i 's/net.ipv4.conf.all.secure_redirects.*/net.ipv4.conf.all.secure_redirects = 0/g' /etc/sysctl.conf
  else
	echo "# net.ipv4.conf.all.secure_redirects" >> /etc/sysctl.conf
	echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
fi

if grep -q ^net.ipv4.conf.all.log_martians /etc/sysctl.conf
then
	sed -i 's/net.ipv4.conf.all.log_martians.*/net.ipv4.conf.all.log_martians = 1/g' /etc/sysctl.conf
  else
	echo "# net.ipv4.conf.all.log_martians" >> /etc/sysctl.conf
	echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
fi

if grep -q ^net.ipv4.conf.default.accept_source_route /etc/sysctl.conf
then
	sed -i 's/net.ipv4.conf.default.accept_source_route.*/net.ipv4.conf.default.accept_source_route = 0/g' /etc/sysctl.conf
  else
	echo "# net.ipv4.conf.default.accept_source_route" >> /etc/sysctl.conf
	echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
fi

if grep -q ^net.ipv4.conf.default.accept_redirects /etc/sysctl.conf
then
	sed -i 's/net.ipv4.conf.default.accept_redirects.*/net.ipv4.conf.default.accept_redirects = 0/g' /etc/sysctl.conf
  else
	echo "# net.ipv4.conf.default.accept_redirects" >> /etc/sysctl.conf
	echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
fi

if grep -q ^net.ipv4.conf.default.secure_redirects /etc/sysctl.conf
then
	sed -i 's/net.ipv4.conf.default.secure_redirects.*/net.ipv4.conf.default.secure_redirects = 0/g' /etc/sysctl.conf
  else
	echo "# net.ipv4.conf.default.secure_redirects" >> /etc/sysctl.conf
	echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
fi

if grep -q ^net.ipv4.icmp_echo_ignore_broadcasts /etc/sysctl.conf
then
	sed -i 's/net.ipv4.icmp_echo_ignore_broadcasts.*/net.ipv4.icmp_echo_ignore_broadcasts = 1/g' /etc/sysctl.conf
  else
	echo "# net.ipv4.icmp_echo_ignore_broadcasts" >> /etc/sysctl.conf
	echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
fi

if grep -q ^net.ipv4.icmp_ignore_bogus_error_responses /etc/sysctl.conf
then
	sed -i 's/net.ipv4.icmp_ignore_bogus_error_responses.*/net.ipv4.icmp_ignore_bogus_error_responses = 1/g' /etc/sysctl.conf
  else
	echo "# net.ipv4.icmp_ignore_bogus_error_responses" >> /etc/sysctl.conf
	echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
fi

if grep -q ^net.ipv4.tcp_syncookies /etc/sysctl.conf
then
	sed -i 's/net.ipv4.tcp_syncookies.*/net.ipv4.tcp_syncookies = 1/g' /etc/sysctl.conf
  else
	echo "# net.ipv4.tcp_syncookies" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
fi

if grep -q ^net.ipv4.conf.all.rp_filter /etc/sysctl.conf
then
	sed -i 's/net.ipv4.conf.all.rp_filter.*/net.ipv4.conf.all.rp_filter = 1/g' /etc/sysctl.conf
  else
	echo "# net.ipv4.conf.all.rp_filter" >> /etc/sysctl.conf
	echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
fi

if grep -q ^net.ipv4.conf.default.rp_filter /etc/sysctl.conf
then
	sed -i 's/net.ipv4.conf.default.rp_filter.*/net.ipv4.conf.default.rp_filter = 1/g' /etc/sysctl.conf
  else
	echo "# net.ipv4.conf.default.rp_filter" >> /etc/sysctl.conf
	echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
fi

if grep -q ^net.ipv4.tcp_timestamps /etc/sysctl.conf
then
	sed -i 's/net.ipv4.tcp_timestamps.*/net.ipv4.tcp_timestamps = 0/g' /etc/sysctl.conf
  else
	echo "# net.ipv4.tcp_timestamps" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_timestamps = 0" >> /etc/sysctl.conf
fi

echo "Sysctl Security for ipv4 are replaced successfully"

/*
#Deny All TCP Wrappers
echo "ALL:ALL" >> /etc/hosts.deny
echo "sshd:ALL" >> /etc/hosts.allow
echo "block all but SSH"
*/

#Disable Uncommon Protocols
echo "install dccp /bin/false" > /etc/modprobe.d/dccp.conf
echo "install sctp /bin/false" > /etc/modprobe.d/sctp.conf
echo "install rds /bin/false" > /etc/modprobe.d/rds.conf
echo "install tipc /bin/false" > /etc/modprobe.d/tipc.conf
echo "Disabled protocols are DCCP, SCTP, RDS, TIPC"

#Ensure Rsyslog is installed
yum -y install rsyslog
echo "rsyslog are instead"

#Enable Rsyslog
systemctl enable rsyslog.service
systemctl start rsyslog.service
echo "Enabled Rsyslog"

#Auditd - Audit Daemon
#Enable auditd Service
systemctl enable auditd.service
systemctl start auditd.service
echo "Audid service Enabled"

#Audit Processes Which Start Prior to auditd
echo "kernel /vmlinuz-version ro vga=ext root=/dev/VolGroup00/LogVol00 rhgb quiet audit=1" >> /etc/grub.conf
echo "Added Audit Processes Which Start Prior to auditd"

#Auditd Number of Logs Retained
if grep -q ^num_logs /etc/audit/auditd.conf
then
	echo "Number of Logs Retained already exist"
	sed -i 's/num_logs.*/num_logs = 5/g' /etc/audit/auditd.conf
	echo "Default:Replaced the count to 5 "

  else
	echo "num_logs = 5" >> /etc/audit/auditd.conf
	echo "Number of Logs Retained is Added & configured to 5"

fi

#Auditd Max Log File Size
#Auditd max_log_file_action
if grep -q ^max_log_file /etc/audit/auditd.conf
then
	echo "Max Log File Size already configured"
	sed -i '/max_log_file_action/d' /etc/audit/auditd.conf
	sed -i 's/max_log_file.*/max_log_file = 30MB/g' /etc/audit/auditd.conf
	echo "Default:Replaced Max Log File Size 30MB "
	echo "max_log_file_action = rotate" >> /etc/audit/auditd.conf
	echo "Default : max_log_file_action is set to rotate"

  else
	echo "max_log_file = 30MB" >> /etc/audit/auditd.conf
	echo "Max Log File Size is Added & configured to 30MB"

fi

#Auditd space_left
#Auditd admin_space_left
echo "Configure auditd to email you when space gets low"
if grep -q ^space_left_action /etc/audit/auditd.conf
then
	echo "space_left is already configured"
	sed -i '/admin_space_left_action/d' /etc/audit/auditd.conf
	sed -i 's/space_left_action.*/space_left_action = email/g' /etc/audit/auditd.conf
	echo "space_left_action is set to email "
	echo "admin_space_left_action = halt" >> /etc/audit/auditd.conf
	echo "admin_space_left_action is set to halt"

  else
	echo "space_left_action = email" >> /etc/audit/auditd.conf
	echo "space_left_action is set to email"

fi

#Auditd mail_acct
if grep -q ^action_mail_acct /etc/audit/auditd.conf
then
	sed -i 's/action_mail_acct.*/action_mail_acct = root/g' /etc/audit/auditd.conf
	echo "action_mail_acct is set to root"

  else
	echo "action_mail_acct = root" >> /etc/audit/auditd.conf
	echo "action_mail_acct is set to root "
fi

#Auditd Rules: /etc/audit/audit.rules
echo "monitor various system files and activities"
echo -e "
# audit_time_rules - Record attempts to alter time through adjtime
-a always,exit -F arch=b64 -S adjtimex -k audit_time_rules

# audit_time_rules - Record attempts to alter time through settimeofday
-a always,exit -F arch=b64 -S settimeofday -k audit_time_rules

# audit_time_rules - Record Attempts to Alter Time Through stime
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime
-k audit_time_rules

# audit_time_rules - Record Attempts to Alter Time Through clock_settime
-a always,exit -F arch=b64 -S clock_settime -k audit_time_rules

# Record Attempts to Alter the localtime File
-w /etc/localtime -p wa -k audit_time_rules

# Record Events that Modify User/Group Information
# audit_account_changes
-w /etc/group -p wa -k audit_account_changes
-w /etc/passwd -p wa -k audit_account_changes
-w /etc/gshadow -p wa -k audit_account_changes
-w /etc/shadow -p wa -k audit_account_changes
-w /etc/security/opasswd -p wa -k audit_account_changes

# Record Events that Modify the System's Network Environment
# audit_network_modifications
-a always,exit -F arch=ARCH -S sethostname -S setdomainname -k audit_network_modifications
-w /etc/issue -p wa -k audit_network_modifications
-w /etc/issue.net -p wa -k audit_network_modifications
-w /etc/hosts -p wa -k audit_network_modifications
-w /etc/sysconfig/network -p wa -k audit_network_modifications

#Record Events that Modify the System's Mandatory Access Controls
-w /etc/selinux/ -p wa -k MAC-policy

#Record Events that Modify the System's Discretionary Access Controls - chmod
-a always,exit -F arch=b32 -S chmod -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chmod  -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - chown
-a always,exit -F arch=b32 -S chown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - fchmod
-a always,exit -F arch=b32 -S fchmod -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchmod -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - fchmodat
-a always,exit -F arch=b32 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - fchown
-a always,exit -F arch=b32 -S fchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchown -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - fchownat
-a always,exit -F arch=b32 -S fchownat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchownat -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - fremovexattr
-a always,exit -F arch=b32 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - fsetxattr
-a always,exit -F arch=b32 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - lchown
-a always,exit -F arch=b32 -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - lremovexattr
-a always,exit -F arch=b32 -S lremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - lsetxattr
-a always,exit -F arch=b32 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - removexattr
-a always,exit -F arch=b32 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod-a always,exit -F arch=b32 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - fchown
-a always,exit -F arch=b32 -S fchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchown -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - fchownat
-a always,exit -F arch=b32 -S fchownat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchownat -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - fremovexattr
-a always,exit -F arch=b32 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - fsetxattr
-a always,exit -F arch=b32 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - removexattr
-a always,exit -F arch=b32 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - setxattr
-a always,exit -F arch=b32 -S setxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Attempts to Alter Logon and Logout Events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins

#Record Attempts to Alter Process and Session Initiation Information
-w /var/run/utmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/wtmp -p wa -k session

#Ensure auditd Collects Unauthorized Access Attempts to Files (unsuccessful)
-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access

#Ensure auditd Collects Information on the Use of Privileged Commands
#
#  Find setuid / setgid programs then modify and uncomment the line below.
#
##  sudo find / -xdev -type f -perm -4000 -o -perm -2000 2>/dev/null
#
# -a always,exit -F path=SETUID_PROG_PATH -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

#Ensure auditd Collects Information on Exporting to Media (successful)
-a always,exit -F arch=ARCH -S mount -F auid>=500 -F auid!=4294967295 -k export

#Ensure auditd Collects File Deletion Events by User
-a always,exit -F arch=ARCH -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete

#Ensure auditd Collects System Administrator Actions
-w /etc/sudoers -p wa -k actions

#Ensure auditd Collects Information on Kernel Module Loading and Unloading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

#Make the auditd Configuration Immutable
-e 2
" >> /etc/audit/audit.rules

#Bulk Remove of Services
# Remove
yum remove xinetd
yum remove rsh-server
yum remove rsh-server
yum remove ypbind
yum remove ypserv
yum remove tftp-server
yum remove cronie-anacron
yum remove vsftpd
echo "removed services
xinetd
rsh-server
rsh-server
ypbind
ypserv
tftp-server
cronie-anacron
vsftpd
"

#Bulk Enable / Disable Services
systemctl disable xinetd
systemctl disable rexec
systemctl disable rsh
systemctl disable ypbind
systemctl disable tftp
systemctl disable certmonger
systemctl disable cgconfig
systemctl disable cgred
systemctl disable cpuspeed
systemctl enable irqbalance
systemctl disable kdump
systemctl disable mdmonitor
systemctl disable messagebus
systemctl disable netconsole
systemctl disable ntpdate
systemctl disable oddjobd
systemctl disable portreserve
systemctl enable psacct
systemctl disable rhsmcertd
systemctl disable saslauthd
systemctl disable smartd
systemctl disable sysstat
systemctl enable crond
systemctl disable atd
systemctl disable named
systemctl disable dovecot
systemctl disable squid
systemctl disable snmpd
echo "Enabled services are
irqbalance
psacct
crond
Disable Services are
xinetd
rexec
rsh
ypbind
tftp
certmonger
cgconfig
cgred
cpuspeed
kdump
mdmonitor
messagebus
netconsole
ntpdate
oddjobd
portreserve
rhsmcertd
saslauthd
smartd
sysstat
atd
named
dovecot
squid
snmpd "

/*
#Disable SSH iptables Firewall rule
-A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
*/

#Disable Avahi Server Software
systemctl disable avahi-daemon
echo "Disabled Avahi Server Software"

#Disable the CUPS Service
systemctl disable cups
echo "Disabled the CUPS Service"

#Remove Sendmail
yum remove sendmail
echo "Removed Sendmail"

#System Audit Logs Must Be Owned By Root
sudo chown root/var/log
echo "changed Audit Logs ownership to root"

#Disable core dumps for all users
sed -i 's/#*               soft    core            0/               hard    core            0/g' /etc/security/limits.conf
echo "Disabled core dumps for all users"

#Buffer Overflow Protection
#Enable ExecShield
sysctl -w kernel.exec-shield=1
echo "kernel.exec-shield = 1" >> /etc/sysctl.conf

#Check / Enable ASLR

sysctl -q -n -w kernel.randomize_va_space=2   #Set runtime for kernel.randomize_va_space
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf

#Prevent Log In to Accounts With Empty Password
sed -i 's/\<nullok\>//g' /etc/pam.d/system-auth

#Secure SSH
#Allow Only SSH Protocol 2
if grep -q ^Protocol /etc/ssh/sshd_config
then
	sed -i 's/protocol.*/Protocol 2/g' /etc/ssh/sshd_config
	echo "protocol set to 2"
  else
	echo "protocol 2" >>  /etc/ssh/sshd_config
	echo "Added protocol 2"
fi

#Limit Users’ SSH Access
if grep -q ^DenyUsers /etc/ssh/sshd_config
then
	sed -i 's/DenyUsers.*/DenyUsers USER1 USER2/g' /etc/ssh/sshd_config
	echo "DenyUsers USER1 USER2 added to /etc/ssh/sshd_config"
  else
	echo "DenyUsers USER1 USER2" >>  /etc/ssh/sshd_config
	echo "DenyUsers USER1 USER2 added to /etc/ssh/sshd_config"
fi

#Set SSH Idle Timeout Interval
sed -i 's/#ClientAliveInterval.*/ClientAliveInterval 0/g' /etc/ssh/sshd_config
echo "removed # for ClientAliveInterval"

#Set SSH Client Alive Count
sed -i 's/#ClientAliveCountMax.*/ClientAliveCountMax 0/g' /etc/ssh/sshd_config
echo "removed # for ClientAliveCountMax"

#Disable SSH Access via Empty Passwords
sed -i 's/#PermitEmptyPasswords.*/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
echo "removed # for PermitEmptyPasswords"

#Do Not Allow SSH Environment Options
sed -i 's/#PermitUserEnvironment.*/PermitUserEnvironment no/g' /etc/ssh/sshd_config
echo "removed # for PermitUserEnvironment"

#Enable PubkeyAuthentication
sed -i 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/g' /etc/ssh/sshd_config
echo "removed # for PubkeyAuthentication"

#Enabled SSH Root Login
sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config
echo "removed # for PermitRootLogin"

#Use Only Approved Ciphers
if grep -q ^Ciphers /etc/ssh/sshd_config
then
	echo "using approved ciphes only"
  else
	echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc" >> /etc/ssh/sshd_config
fi

#Prompt OS update installation
echo "Prompt OS update installation"
yum -y install yum-cron
chkconfig yum-cron on
