#!/bin/bash
 
# By: Dr.v
# centos7_system_init 系统初始化设置
# ZIP文件需要传到非root用户家目录中。
# 运行脚本必须要root用户，脚本户参数是用于切换root用的，其他用户均不能切换root。
# 运行规则 sh centos7_system_init.sh user
 

#username
UserName=$1
#CPU编译数量
UJ=`awk '/processor/{i++}END{print i}' /proc/cpuinfo`
#文件目录
BashDir=/home/"$UserName"/centos7_init

#检测当前用户是否是root用户
if [[ "$(whoami)" != "root" ]]; then
  
    echo "please run this script as root ." >&2
    exit;
fi

#检测用户是否输入
if [ "$UserName" = "" ]; then
	echo "Install username is null"
	exit;
fi
#检测文件
#if [ ! -f "/home/$UserName/centos7_init.zip" ]; then
#    echo "Can not find a file."
#    exit;
#fi

#解压文件
#cd /home/$UserName
#unzip centos7_init.zip

#检测是否有centos7_ini这个文件夹
if [ ! -d "$BashDir" ]; then
    echo "No folder was found."
    exit;
fi
#disable selinux
selinux_config(){
sed -i '/SELINUX/s/enforcing/disabled/' /etc/selinux/config
setenforce 0
systemctl stop postfix.service
systemctl disable postfix.service
echo "[Success] Selinux Stop" >$BashDir/System_conf.log
}
  
iptables_config(){
#systemctl start firewalld
#systemctl enable firewalld
#firewall-cmd --permanent --zone=public --add-service=http
#firewall-cmd --permanent --zone=public --add-service=https
#firewall-cmd --permanent --zone=public --add-port=8080/tcp
#firewall-cmd --permanent --add-forward-port=port=80:proto=tcp:toport=8080
#firewall-cmd --reload
systemctl stop firewalld.service
systemctl disable firewalld.service
#yum -y install iptables-services
#cat > /etc/sysconfig/iptables << EOF
# Firewall configuration written by system-config-securitylevel
# Manual customization of this file is not recommended.
#*nat
#:PREROUTING ACCEPT [224:17196]
#:POSTROUTING ACCEPT [9:646]
#:OUTPUT ACCEPT [9:646]
#-A PREROUTING -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 8080
#*filter
#:INPUT ACCEPT [379:44557]
#:FORWARD ACCEPT [0:0]
#:OUTPUT ACCEPT [588:54321]
#:syn-flood - [0:0]
#-A INPUT -i lo -j ACCEPT
#-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
#-A INPUT -p tcp -m state --state NEW -m tcp --dport 65000 -j ACCEPT
#-A INPUT -p tcp -m state --state NEW -m tcp --dport 80 -j ACCEPT
#-A INPUT -p icmp -m limit --limit 100/sec --limit-burst 100 -j ACCEPT
#-A INPUT -p icmp -m limit --limit 1/s --limit-burst 10 -j ACCEPT
#ICMP时间戳低漏洞问题加下面两行
#-A INPUT -p ICMP --icmp-type timestamp-request -j DROP
#-A INPUT -p ICMP --icmp-type timestamp-reply -j DROP
#-A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j syn-flood
#-A INPUT -j REJECT --reject-with icmp-host-prohibited
#-A syn-flood -p tcp -m limit --limit 3/sec --limit-burst 6 -j RETURN
#-A syn-flood -j REJECT --reject-with icmp-port-unreachable
#COMMIT
#EOF
#/sbin/service iptables restart
echo "[Success] Firewalld Stop" >>$BashDir/System_conf.log
}
#yumconfig(){
#	cp /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak
#	echo "[base]" > /etc/yum.repos.d/CentOS-Base.repo
#	echo "name=CentOS-$releasever - Base" >> /etc/yum.repos.d/CentOS-Base.repo
#	echo "baseurl=http://" >> /etc/yum.repos.d/CentOS-Base.repo
#	echo "gpgcheck=1" >> /etc/yum.repos.d/CentOS-Base.repo
#	echo "gpgkey=http:///RPM-GPG-KEY-CentOS-7" >> /etc/yum.repos.d/CentOS-Base.repo
#}
yums(){
	yum -y install gnutls-devel perl gcc make kernel-headers kernel-devel libdb-devel mesa qt redhat-lsb openssl-devel net-tools vim unzip telnet
}


path_upgdate(){
#centos7不需要升级glibc和bash，如果没装ntp服务器端，也不用升级ntp，下面升级wget
#安装lrzsz
cd $BashDir
tar zxvf lrzsz-0.12.20.tar.gz -C /usr/local/
mv /usr/local/lrzsz-0.12.20 /usr/local/lrzsz
cd /usr/local/lrzsz/
./configure && make -j$UJ && make install
cd /usr/bin/
ln -s /usr/local/bin/lrz rz
ln -s /usr/local/bin/lsz sz
echo "[Success] Lrzsz Install" >>$BashDir/System_conf.log
#更新openssl 需要支持库zlib
cd $BashDir
/sbin/service sshd stop
yum -y remove openssh
mkdir -p /usr/local/zlib
tar zxvf zlib-1.2.8.tar.gz 
cd zlib-1.2.8
./configure --prefix=/usr/local/zlib && make -j$UJ && make install 

cd $BashDir
opensslv=openssl-1.0.2m
mkdir -p /usr/local/openssl
tar zxvf $opensslv.tar.gz
cd $opensslv
./config --prefix=/usr/local/openssl -fPIC no-gost && make depend -j$UJ && make install
\mv /usr/bin/openssl /usr/bin/openssl.old
\mv /usr/include/openssl /usr/include/openssl.old
ln -s /usr/local/openssl/bin/openssl /usr/bin/openssl
ln -s /usr/local/openssl/include/openssl /usr/include/openssl
echo "/usr/local/openssl/lib" >> /etc/ld.so.conf
/sbin/ldconfig -v
#openssl version -a
echo "[Success] Openssl Update Version:"`openssl version | awk 'NR==1{print $2}'` >>$BashDir/System_conf.log
unset opensslv

#更新openssh
cd $BashDir
opensshv=openssh-7.5p1
mv /etc/ssh /etc/ssh.old
tar -zxvf $opensshv.tar.gz
cd $opensshv
./configure --prefix=/usr --sysconfdir=/etc/ssh  --with-zlib=/usr/local/zlib --with-ssl-dir=/usr/local/openssl  --with-md5-passwords --mandir=/usr/share/man && make -j$UJ && make install
cp -p contrib/redhat/sshd.init /etc/init.d/sshd
chmod +x /etc/init.d/sshd
sed -i 's@/sbin/restorecon /etc/ssh/ssh_host_key.pub@#/sbin/restorecon /etc/ssh/ssh_host_key.pub@' /etc/init.d/sshd 
chkconfig --add sshd
\cp sshd_config /etc/ssh/sshd_config
\cp sshd /usr/sbin/sshd
service sshd start
echo "[Success] Openssh Update Version:"$opensshv >>$BashDir/System_conf.log
unset opensshv
#安装Wget
cd $BashDir
tar zxvf wget-1.19.tar.gz -C /usr/local/
mv /usr/local/wget-1.19 /usr/local/wget
cd /usr/local/wget/
./configure --with-ssl=/usr/local/openssl && make -j$UJ && make install
\cp /usr/local/wget/src/wget /usr/bin/wget
echo "[Success] Wget Install Version:"`wget -V | awk 'NR==1{print $2 $3}'` >>$BashDir/System_conf.log

#安装ntp
cd $BashDir
tar zxvf ntp-4.2.8p10.tar.gz -C /usr/local/
cd /usr/local/ntp-4.2.8p10
./configure --prefix=/usr/local/ntp --enable-all-clocks --enable-parse-clocks && make -j$UJ && make install
rm -rf /usr/local/ntp-4.2.8p10
echo "[Success] NTP Install" >>$BashDir/System_conf.log
}
#set ntp
zone_time(){
    cp  /usr/share/zoneinfo/Asia/Shanghai  /etc/localtime
    printf 'ZONE="Asia/Shanghai"\nUTC=false\nARC=false' > /etc/sysconfig/clock
    /usr/sbin/ntpdate 172.51.116.11
    echo "* */30 * * * /usr/local/ntp/bin/ntpdate 172.51.116.11 > /dev/null 2>&1" >> /var/spool/cron/root;chmod 600 /var/spool/cron/root
    echo 'LANG="en_US.UTF-8"' > /etc/sysconfig/i18n
    sed -i 's/LANG="zh_CN.UTF-8"/LANG="en_US.UTF-8"/' /etc/locale.conf
    #echo 'LANG="zh_CN.UTF-8"' > /etc/sysconfig/i18n
    source  /etc/sysconfig/i18n
    echo "[Success] Time Ntpdate 172.51.116.11" >>$BashDir/System_conf.log
} 
#set ulimit
ulimit_config(){
echo "ulimit -SHn 1048576" >> /etc/rc.local
sed -e '$a DefaultLimitCORE=infinity\nDefaultLimitNOFILE=1048576\nDefaultLimitNPROC=1048576' -i /etc/systemd/system.conf
cat >> /etc/security/limits.conf << EOF
 *           soft   nofile       1048576
 *           hard   nofile       1048576
 *           soft   nproc        1048576
 *           hard   nproc        1048576
EOF
sed -i 's/4096/1048576/' /etc/security/limits.d/20-nproc.conf 
sed -e '/root       soft    nproc     unlimited/a\*           soft   nofile       1048576\n*           hard   nofile       1048576' -i /etc/security/limits.d/20-nproc.conf 
echo "[Success] Ulimit Revise" >>$BashDir/System_conf.log
}
 
#set ssh
sshd_config(){
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
#sed -i 's/#GSSAPIAuthentication no$/GSSAPIAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#UseDNS no/UseDNS no/' /etc/ssh/sshd_config
sed -i 's/#Port 22/Port 32200/' /etc/ssh/sshd_config
echo 'Protocol 2' >> /etc/ssh/sshd_config
#sed -i '/^#UsePAM no/a UsePAM yes' /etc/ssh/sshd_config
#如果重启失败，多半是selinux没关，或者防火墙端口没放行
service sshd restart
systemctl start crond
echo "[Success] Port 32200 | PermitRootLogin Yes" >>$BashDir/System_conf.log
}

pass_config(){
sed -i '25s/99999/89/' /etc/login.defs
sed -i '26s/0/10/' /etc/login.defs	
sed -i 's/password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=/password    requisite     pam_pwquality.so try_first_pass retry=3 dcredit=-1 lcredit=-1 ucredit=-1 ocredit=-1 minlen=8/' /etc/pam.d/system-auth
echo TMOUT=300 >> /etc/profile
echo "export  TMOUT=300" >> /etc/profile
echo "umask 027" >> /etc/profile
echo "[Success] Password Config" >>$BashDir/System_conf.log
}

user_del(){
userdel lp
userdel sync
userdel halt
userdel operator
userdel games
userdel nobody
echo "[Success] Clean User" >>$BashDir/System_conf.log
}

su_config(){
line2=$(sed -n "/^auth/=" /etc/pam.d/su|tail -1 )
sed -i "${line2}a auth\ \ \ \ \ \ required\ \ \ \ pam_wheel.so\ use_uid" /etc/pam.d/su
unset line2
usermod -G wheel $UserName
}

log_config(){
echo -e "*.*\t@127.0.0.1" >> /etc/rsyslog.conf
echo "*.err;kern.debug;daemon.notice /var/log/messages" >> /etc/rsyslog.conf
echo "auth.info   /var/log/authlog" >> /etc/rsyslog.conf
cat $BashDir/bashrc.txt >> /etc/bashrc 
source /etc/bashrc 
chmod 0640 /var/log/messages
chmod 0640 -R /var/log/
touch /var/log/authlog
chmod 0640 /var/log/authlog
chmod 0640 /etc/rsyslog.d/listen.conf
chmod 0640 /var/log/boot.log
systemctl restart rsyslog
chmod 0640 /var/log/*.log
}
  
#set sysctl 网络线程优化
sysctl_config(){
cp /etc/sysctl.conf /etc/sysctl.conf.bak
cat > /etc/sysctl.conf << EOF
 fs.file-max = 1048576
 net.ipv4.ip_forward = 0
 net.ipv4.conf.default.rp_filter = 1
 net.ipv4.conf.default.accept_source_route = 0
 kernel.sysrq = 0
 kernel.core_uses_pid = 1
 net.ipv4.tcp_syncookies = 1
 kernel.msgmnb = 65536
 kernel.msgmax = 65536
 kernel.shmmax = 68719476736
 kernel.shmall = 4294967296
 net.ipv4.tcp_max_tw_buckets = 6000
 net.ipv4.tcp_sack = 1
 net.ipv4.tcp_window_scaling = 1
 net.ipv4.tcp_rmem = 4096 87380 4194304
 net.ipv4.tcp_wmem = 4096 16384 4194304
 net.core.wmem_default = 8388608
 net.core.rmem_default = 8388608
 net.core.rmem_max = 16777216
 net.core.wmem_max = 16777216
 net.core.netdev_max_backlog = 262144
 net.core.somaxconn = 32768
 net.ipv4.tcp_max_orphans = 3276800
 net.ipv4.tcp_max_syn_backlog = 262144
 net.ipv4.tcp_timestamps = 0
 net.ipv4.tcp_synack_retries = 1
 net.ipv4.tcp_syn_retries = 1
 net.ipv4.tcp_tw_recycle = 1
 net.ipv4.tcp_tw_reuse = 1
 net.ipv4.tcp_mem = 94500000 915000000 927000000
 net.ipv4.tcp_fin_timeout = 1
 net.ipv4.tcp_keepalive_time = 1200
 net.ipv4.ip_local_port_range = 1024 65535
EOF
/sbin/sysctl -p
echo "[Success] Network Optimize" >>$BashDir/System_conf.log
}

#记录每次bash命令的执行时间
history_time(){
time="HISTTIMEFORMAT=\"%Y-%m-%d\ %H:%M:%S \""
grep "$time" /etc/profile >> /etc/null
if [ $? = "0" ];then
echo "记录每次bash命令的执行时间已经做过"
else
line=$(sed -n "/export\ PATH\ USER/=" /etc/profile| tail -n1)
sed -i "${line}a HISTTIMEFORMAT=\"%Y-%m-%d\ %H:%M:%S \"\nexport\ HISTTIMEFORMAT" /etc/profile
echo "记录每次bash命令的执行时间已经成功"
fi	
echo "[Success] History Config" >>$BashDir/System_conf.log
source /etc/profile
}

vmware_tools(){
cd $BashDir
tar zxvf VMwareTools-10.0.9-3917699.tar.gz
cd $BashDir/vmware-tools-distrib
./vmware-install.pl -d &&
echo "[Success] Vmware_tools Install" >>$BashDir/System_conf.log	
}



main(){
selinux_config
iptables_config
#yumconfig
yums
path_upgdate
zone_time
ulimit_config
#sysctl_config
sshd_config
pass_config
user_del
su_config
log_config
history_time
vmware_tools
}
main

cat $BashDir/System_conf.log
#检测日志权限
LOGDIR=`cat /etc/rsyslog.conf | grep -v "^[[:space:]]*#"|awk '(($2!~/@/) && ($2!~/*/) && ($2!~/-/)) {print $2}'`;
ls -l $LOGDIR 2>/dev/null|grep -v "[r-][w-]-[r-]-----"|awk '{print $1" "$8" "$9}';
unset LOGDIR