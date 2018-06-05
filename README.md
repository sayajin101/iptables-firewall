# iptables-firewall
Iptables Firewall Script with start, stop, restart, status functunality


# Install iptables
yum install iptables-services

# Edit iptable firewall rules
nano /etc/sysconfig/iptables

# Stop & Disable firewalld
systemctl stop firewalld
systemctl disable firewalld
systemctl mask firewalld

# Start & Enable iptables
systemctl enable iptables
systemctl start iptables
