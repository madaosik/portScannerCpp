//
// Created by Adam Láníček on 2019-04-14.
//

#include "Scanner.h"

Scanner::Scanner(vector<int> &ports, ArgParser& args ) : ports(ports), args(args) {
    this->args = args;
    this->ports = ports;
    this->resolve_target_info();
    this->get_iface_name();
    this->find_match_host_if_fam();

    this->state_map[OPEN] = "open";
    this->state_map[CLOSED] = "closed";
    this->state_map[FILTERED] = "filtered";
    this->state_map[NOT_CHECKED] = "scan failure";
}

void Scanner::run_scan() {
    State state;
    int port;

    for (auto t = this->ports.begin(); t!=this->ports.end(); ++t) {
        port = *t;
        state = this->scan_port(port);
        this->results_map[port] = state;
    }
}

// Function for checksum calculation. From the RFC,
// the checksum algorithm is:
//  "The checksum field is the 16 bit one's complement of the one's
//  complement sum of all 16 bit words in the header.  For purposes of
//  computing the checksum, the value of the checksum field is zero."
unsigned short Scanner::check_sum(unsigned short *buf, int n_words)
{
    unsigned long sum;
    for(sum=0; n_words>0; n_words--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void Scanner::resolve_target_info() {
    struct addrinfo hints;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = 0;
    hints.ai_flags = AI_ADDRCONFIG | AI_CANONNAME;
    hints.ai_protocol = 0;
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;


    int resolve_result = getaddrinfo(this->args.getHost().c_str(), 0, &hints, &(this->candidates));
    if (resolve_result != 0)
        Logger::error_exit(gai_strerror(resolve_result));

    return;
}

void Scanner::print_header() {
    struct sockaddr_in *addr;
    addr = (struct sockaddr_in *)this->candidates->ai_addr;

    cout << "\n";
    if (strlen(this->host_name) != 0)
        cout << "Interesting ports on " << this->candidates->ai_canonname << " (" << inet_ntoa((struct in_addr)addr->sin_addr) << "):\n";
    else {
        cout << "Interesting ports on " << inet_ntoa((struct in_addr)addr->sin_addr) << "\n";
    }
    cout << "PORT\t\tSTATE\n";
}

void Scanner::print_results(string protocol) {
    for (const auto &p : this->results_map) {
        if (to_string(p.first).length() > 2)
            cout << p.first << protocol << "\t" << this->state_map[p.second] << "\n";
        else
            cout << p.first << protocol << "\t\t" << this->state_map[p.second] << "\n";
    }
}

void Scanner::get_iface_name() {
    if (getifaddrs(&(this->ifaddr)) != 0)
        Logger::error_exit("Error retrieving interface name");
    else
        return;
}

void Scanner::find_match_host_if_fam()
{
    unsigned short fam_host;
    unsigned short dev_fam;
    bool loop_break = false;

    for (this->target = this->candidates; this->target != NULL; this->target = this->target->ai_next)
    {
        fam_host = this->target->ai_addr->sa_family;
        for(this->ifa = this->ifaddr; this->ifa != NULL; this->ifa = this->ifa->ifa_next)
        {
            dev_fam = this->ifa->ifa_addr->sa_family;
            if( fam_host != dev_fam) { continue;}
            if( strcmp( this->ifa->ifa_name, "lo" ) == 0) { continue;}
            if( args.getIface_name() !=  "" ) {
                if (strcmp(this->args.getHost().c_str(), this->ifa->ifa_name) != 0) {
                    continue;
                }
            }
            loop_break = true;
            break;
        }
        if (loop_break == true)
            break;
    }
    if(this->target == NULL) { Logger::error_exit("No combination for host and interface has been identified!!"); }
}

// Source: https://stackoverflow.com/questions/2371910/how-to-get-the-port-number-from-addrinfo-in-unix-c

in_port_t Scanner::get_in_port(struct sockaddr* sa) {
    if (sa->sa_family == AF_INET) {
        return (((struct sockaddr_in*)sa)->sin_port);
    }

    return (((struct sockaddr_in6*)sa)->sin6_port);
}








