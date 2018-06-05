#!/bin/bash

general() {
    #######################
    # Variables to Modify #
    #######################
    # Interface connected to the Internet
    PUB_IF="eno1";
    PUB_IP="x.x.x.x/32"

    # Interface connected to the Local LAN
    LAN_IF="eno2"
    LAN_IP="x.x.x.x/32"
    #######################



    # Define Path Variables
    MODP=$(which modprobe);
    IPT=$(which iptables);
    SYSCTL=$(which sysctl);
    rm -f /etc/sysconfig/iptables;

    # Get Hostname
    HOSTNAME=`hostname`;
};

flush() {
    # Set default chain policies
    ${IPT} -P INPUT ACCEPT
    ${IPT} -P FORWARD ACCEPT
    ${IPT} -P OUTPUT ACCEPT

    # Flush all current tables
    ${IPT} -t nat -F
    ${IPT} -t nat -X
    ${IPT} -t mangle -F
    ${IPT} -t mangle -X
    ${IPT} -F
    ${IPT} -X
}

kernel() {
    ### Set Kernel and Protocol Options ###
    # Automatically restart 10 seconds after Kernel Panic
        echo "10" > /proc/sys/kernel/panic;
    # IP Forwarding
        echo "1" > /proc/sys/net/ipv4/ip_forward;
    # Enable SYN Cookies (syn-flooding attacks)
        echo "1" > /proc/sys/net/ipv4/tcp_syncookies;
    # Starting IP Bogus Error Response Protection
        echo "1" > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses;
    # Anti Spoofing (no asymmetric routes)
        #for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo "0" > $f; done;             # Turn off source routing checks, when using firewall mangle rules to redirect traffic
        for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo "1" > $f; done;
        for f in /proc/sys/net/ipv4/conf/*/send_redirects; do echo "0" > $f; done;
    # Disable source routing
        for f in /proc/sys/net/ipv4/conf/*/accept_source_route; do echo "0" > $f; done;
    # Log impossible addresses
        for f in /proc/sys/net/ipv4/conf/*/log_martians; do echo "1" > $f; done;
    # Disable ICMP redirects
        for f in /proc/sys/net/ipv4/conf/*/accept_redirects; do echo "0" > $f; done;
    # Disable ICMP echo-request to broadcast addresses (Smurf amplifier)
        echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts;
    # Set local port range
        echo "50000 60999" > /proc/sys/net/ipv4/ip_local_port_range;

    # Load modules
    ${MODP} ip_conntrack;
}

iptableRules() {
    # Allow icmp packets
    ${IPT} -N icmp-allowed
    ${IPT} -A icmp-allowed -m state --state NEW -p icmp --icmp-type echo-request -j ACCEPT
    ${IPT} -A icmp-allowed -m state --state NEW -p icmp --icmp-type source-quench -j ACCEPT
    ${IPT} -A icmp-allowed -m state --state NEW -p icmp --icmp-type time-exceeded -j ACCEPT
    ${IPT} -A icmp-allowed -m state --state NEW -p icmp --icmp-type destination-unreachable -j ACCEPT
    ${IPT} -A icmp-allowed -j DROP

    # Log Unspecified Traffic
    ${IPT} -N unspecified
    ${IPT} -A unspecified -m limit --limit 5/minute -j LOG --log-prefix "Unspecified-Traffic: "
    ${IPT} -A unspecified -j DROP

    # Log Unmatched Traffic
    ${IPT} -N unmatched
    ${IPT} -A unmatched -m limit --limit 5/minute -j LOG --log-prefix "Unmatched-Traffic: "
    ${IPT} -A unmatched -j RETURN

    # Make forwarding statefull
    ${IPT} -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    ${IPT} -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    ${IPT} -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
    ${IPT} -A INPUT -m state --state INVALID -j DROP
    ${IPT} -A OUTPUT -m state --state INVALID -j DROP
    ${IPT} -A FORWARD -m state --state INVALID -j DROP

    # Unlimited traffic for loopback
    ${IPT} -A INPUT -i lo -j ACCEPT
    ${IPT} -A OUTPUT -o lo -j ACCEPT

    # General ICMP
    ${IPT} -A INPUT -p icmp -j icmp-allowed
    ${IPT} -A OUTPUT -p icmp -j icmp-allowed
    ${IPT} -A FORWARD -p icmp -j icmp-allowed

    # Block sync
    ${IPT} -A INPUT -i ${PUB_IF} -p tcp ! --syn -m state --state NEW  -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Drop Sync: "
    ${IPT} -A INPUT -i ${PUB_IF} -p tcp ! --syn -m state --state NEW -j DROP

    # Block Fragments
    ${IPT} -A INPUT -i ${PUB_IF} -f -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Fragments Packets: "
    ${IPT} -A INPUT -i ${PUB_IF} -f -j DROP

    # Block bad stuff
    ${IPT} -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
    ${IPT} -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
    ${IPT} -A INPUT -p tcp --tcp-flags ALL NONE -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "NULL Packets: "
    ${IPT} -A INPUT -p tcp --tcp-flags ALL NONE -j DROP                                         # NULL packets
    ${IPT} -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
    ${IPT} -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "XMAS Packets: "
    ${IPT} -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP                                  # XMAS
    ${IPT} -A INPUT -p tcp --tcp-flags FIN,ACK FIN -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Fin Packets Scan: "
    ${IPT} -A INPUT -p tcp --tcp-flags FIN,ACK FIN -j DROP                                      # FIN packet scans
    ${IPT} -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

    # Create forwarding chains
    ${IPT} -N pub-fire
    ${IPT} -N lan-fire

    # Set jumps for input chain
    ${IPT} -A INPUT -i ${PUB_IF} -d ${PUB_IP} -j pub-fire
    ${IPT} -A INPUT -i ${LAN_IF} -d ${LAN_IP} -j lan-fire
    ${IPT} -A INPUT -j unspecified

    # Internet to Firewall Connections
    ${IPT} -A pub-fire -m state --state NEW -p udp --dport 5060 -j ACCEPT                          # SIP
    ${IPT} -A pub-fire -m state --state NEW -p udp --dport 5061 -j ACCEPT                          # SIP TLS
    ${IPT} -A pub-fire -m state --state NEW -p udp --dport 10000:20000 -j ACCEPT                   # RTP Media
    ${IPT} -A pub-fire -m state --state NEW -p tcp --dport 3333 -j ACCEPT                          # SSH
    ${IPT} -A pub-fire -j unmatched                                                                # Log all unmatched traffic
    ${IPT} -A pub-fire -j DROP                                                                     # Drop non-accepted connections

    # LAN to Firewall Connection
    ${IPT} -A lan-fire -m state --state NEW -p tcp -s 10.11.12.13/30 --dport 7788  -j ACCEPT       # DRBD Sync
    ${IPT} -A lan-fire -m state --state NEW -p vrrp -d 224.0.0.0/8 -j ACCEPT                       # Keepalive Daemon
    ${IPT} -A lan-fire -j unmatched                                                                # Log all unmatched traffic
    ${IPT} -A lan-fire -j DROP                                                                     # Drop non-accepted connections

    # Allow all connections from Firewall
    ${IPT} -A OUTPUT -m state --state NEW -j ACCEPT                                                # Accept all outbound traffic
    ${IPT} -A OUTPUT -j unmatched                                                                  # Log all unmatched traffic
}

action="${1}";
case ${action} in
    start)
        general;
        flush;
        kernel;
        iptableRules;
        echo -e "\nFirewall Enabled\n";
    ;;
    stop)
        general;
        flush;
        echo -e "\nFirewall Disabled\n";
    ;;
    status)
        echo -e "\nThis function is not yet built in\n";
    ;;
    *)
        echo -e "Enter a valid command: [ start | stop | status ]";
    ;;
esac;
