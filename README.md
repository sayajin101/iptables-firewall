# iptables-firewall
Iptables Firewall Script with start, stop, restart, status functunality

# Setup
- Add firewall.sh content to /etc/sysconfig/firewall.sh
- Change firewall.sh permissions
  - chmod 755 /etc/sysconfig/firewall.sh
- Add firewall.service content to /etc/systemd/system/firewall.service

- Install iptables
  - yum install iptables-services

- Remove default iptable firewall rules
   - rm /etc/sysconfig/iptables

- Stop & Disable firewalld
  - systemctl stop firewalld
  - systemctl disable firewalld
  - systemctl mask firewalld
  
- Start & enable firewall service
  - service enable firewall
  - service start firewall
