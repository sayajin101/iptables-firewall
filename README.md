# iptables-firewall
Iptables Firewall Script with start, stop, restart, status functunality

# Setup
* Install iptables
 yum install iptables-services

* Remove default iptable firewall rules
 rm /etc/sysconfig/iptables

* Stop & Disable firewalld
 systemctl stop firewalld
 systemctl disable firewalld
 systemctl mask firewalld

* Start & Enable iptables
 systemctl enable iptables
 systemctl start iptables
