//
// Created by Adam Láníček on 2019-04-14.
//

#include "UdpScanner.h"

UdpScanner::UdpScanner(vector<int>& ports) : Scanner(ports) {}

// Function for checksum calculation. From the RFC,
// the checksum algorithm is:
//  "The checksum field is the 16 bit one's complement of the one's
//  complement sum of all 16 bit words in the header.  For purposes of
//  computing the checksum, the value of the checksum field is zero."
unsigned short UdpScanner::check_sum(unsigned short *buf, int n_words)
{
    unsigned long sum;
    for(sum=0; n_words>0; n_words--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}


State UdpScanner::scan_port(int port) {
    State state = OPEN;
    int sd;
// No data/payload just datagram
    char buffer[DATAGRAM_SIZE];
// Our own headers' structures
    struct ipheader *ip = (struct ipheader *) buffer;
    struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));
// Source and destination addresses: IP and port
    struct sockaddr_in sin, din;
    int one = 1;
    const int *val = &one;

    memset(buffer, 0, DATAGRAM_SIZE);

// Create a raw socket with UDP protocol
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if(sd < 0) {
        perror("socket() error");
        Logger::error_exit("Socket() function error");
    }
    else
        Logger::log_status("socket() - Using SOCK_RAW socket and UDP protocol is OK.\n");

// The source is redundant, may be used later if needed
// The address family
    //sin.sin_family = AF_INET;
    din.sin_family = AF_INET;
// Port numbers
    //sin.sin_port = htons(SRC_PORT);
    din.sin_port = htons(port);
// IP addresses
    //sin.sin_addr.s_addr = inet_addr(SRC_IP);
    din.sin_addr.s_addr = inet_addr(this->host_ip);

// Fabricate the IP header or we can use the
// standard header structures but assign our own values.
    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 16; // Low delay
    ip->iph_len = sizeof(struct ipheader) + sizeof(struct udpheader);
    ip->iph_ident = htons(54321);
    ip->iph_ttl = 64; // hops
    ip->iph_protocol = 17; // UDP
// Source IP address, can use spoofed address here!!!
    ip->iph_sourceip = inet_addr(SRC_IP);
// The destination IP address
    ip->iph_destip = inet_addr(this->host_ip);

// Fabricate the UDP header. Source port number, redundant
    udp->udph_srcport = htons(SRC_PORT);
// Destination port number
    udp->udph_destport = htons(port);
    udp->udph_len = htons(sizeof(struct udpheader));
// Calculate the checksum for integrity
    ip->iph_chksum = this->check_sum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
// Inform the kernel do not fill up the packet structure. we will build our own...
    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        Logger::error_exit("Setsockopt() error");
    }


// Send loop, send for every 2 second for 100 count
//    printf("Trying...\n");
//    printf("Using raw socket and UDP protocol\n");
//    printf("Using Source IP: %s port: %u, Target IP: %s port: %u.\n", argv[1], atoi(argv[2]), argv[3], atoi(argv[4]));

    int retval;
    //for(count = 1; count <=20; count++)

    retval = sendto(sd, buffer, ip->iph_len, 0, (struct sockaddr *)&din, sizeof(din));

    if(retval < 0) {
        Logger::error_exit(string(strerror(errno))); }
    else {
        Logger::log_status("Sendto() succeeded");
    }

    sleep(2);
    //}
    close(sd);

    return state;
}

