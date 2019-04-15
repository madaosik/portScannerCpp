//
// Created by Adam Láníček on 2019-04-14.
//

#include "Scanner.h"

Scanner::Scanner(vector<int> &ports) : ports(ports) {
    this->ports = ports;
    this->state_map[OPEN] = "open";
    this->state_map[CLOSED] = "closed";
    this->state_map[FILTERED] = "filtered";
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

void Scanner::set_host_ip(string& host) {
    int n = host.length();
    char host_char[n+1];
    strcpy(host_char, host.c_str());

    if (validate_ip(host_char)) {
        strcpy(this->host_ip, host_char);
        Logger::log_status("IP used for the extraction", string(this->host_ip));
        return;
    }
    // we need to convert the hostname to IP
    this->host_name = host;
    struct hostent *host_info;
    host_info = gethostbyname(host_char);

    if (!host_info)
        Logger::error_exit("Cannot get the IP address for the entered hostname");

    inet_ntop(AF_INET,host_info->h_addr,this->host_ip,MAX_LEN);
    Logger::log_status("Extracted IP from the hostname", string(this->host_ip));
}

bool Scanner::validate_ip(char *host) {
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET,host,&(sa.sin_addr));
    return result != 0;
}

void Scanner::print_header() {
    cout << "\n";
    if (!(this->host_name.empty()))
        cout << "Interesting ports on " << this->host_name << " (" << this->host_ip << "):\n";
    else {
        cout << "Interesting ports on " << this->host_ip << "\n";
    }
    cout << "PORT\t\tSTATE\n";
}

void Scanner::print_results(string protocol) {
    for (const auto &p : this->results_map) {
        cout << p.first << protocol << "\t\t" << this->state_map[p.second] << "\n";
    }
}






