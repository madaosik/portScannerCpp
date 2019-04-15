//
// Created by Adam Láníček on 2019-04-01.
//

#include "Argparser.h"

ArgParser::ArgParser (int argc, char **argv) {
    int opt;
    int option_index = 0;
    Protocol protocol;

    static struct option long_opts[] = {
            {"pt", required_argument, NULL, 't'},
            {"pu", required_argument, NULL, 'u'},
            {0, 0, 0, 0}
    };


    while ((opt = getopt_long(argc, argv, ":t:u:i:", long_opts, &option_index)) != EOF) {
        switch(opt)
        {
            case 'i':
                this->iface_name = optarg;
                Logger::log_status("Entered interface", optarg);
                break;
            case 't':
                Logger::log_status("Entered TCP ports", optarg);
                protocol = TCP;
                parse_ports(protocol, optarg);
                break;
            case 'u':
                Logger::log_status("Entered UDP ports", optarg);
                protocol = UDP;
                parse_ports(protocol, optarg);
                break;
            case '?':
                break;
        }
    }

    if (optind == argc) {
        Logger::error_exit("Host/IP option missing! Terminating the program");
    } else {
        Logger::log_status("Hostname/IP", argv[optind]);
        this->host = argv[optind];
    }

    if (argv[++optind] != NULL) {
        Logger::error_exit("Unexpected argument has been provided");
    }
}

void ArgParser::parse_ports(Protocol protocol, char *port_str){
    char *p;
    long converted = strtol(port_str, &p, 10);

    if (!(*p)) { // Port string is just one number
        if (protocol == TCP) {
            Logger::log_status("TCP port to be scanned", to_string(converted));
            this->tcpPorts.insert(this->tcpPorts.begin(), converted);
        } else {
            Logger::log_status("UDP port to be scanned", to_string(converted));
            this->udpPorts.insert(this->udpPorts.begin(), converted);
        }
        return;
    }

    // Port string is not directly convertible to a number
    string s(port_str);
    string comma(COMMA);
    string dash(DASH);
    string delimiter;

    if (contains_char(s,comma) && contains_char(s,dash)) {
        Logger::error_exit("Unexpected format of the port input argument, both range and enumeration symbols are present!");
    } else if (!(contains_char(s,comma)) && (!(contains_char(s,dash))))
        Logger::error_exit("Unexpected format of the port input argument, missing comma or a dash");

    if (contains_char(s, comma)) {
        delimiter = comma;
    } else if (contains_char(s, dash)) {
        if (is_range_valid(s)) {
            delimiter = dash;
        } else {
            Logger::error_exit("Multiple dashes have been identified in port range specification");
        }
    }

    if (protocol == TCP) {
        if (delimiter == COMMA)
            this->tcpPorts = set_port_values(s);
        else
            this->tcpPorts = set_port_range(s);
    } else {
        if (delimiter == COMMA)
            this->udpPorts = set_port_values(s);
        else
            this->udpPorts = set_port_range(s);
    }
}


vector<int> ArgParser::set_port_values(string &s) {
    vector<int> v;
    size_t pos = 0;
    string token;
    string delimiter(COMMA);
    int port;

    while((pos = s.find(delimiter)) != string::npos) {
        token = s.substr(0, pos);
        port = convert_to_int(token);
        check_port_range(port);
        v.insert(v.end(), port);
        s.erase(0, pos + delimiter.length());
    }
    port = convert_to_int(s);
    check_port_range(port);
    v.insert(v.end(),port);

    return v;
}

vector<int> ArgParser::set_port_range(string &s) {
    vector<int> v;
    string delimiter(DASH);
    size_t dash_pos = 0;
    string token;
    int i, range_start, range_end;

    dash_pos = s.find(delimiter);
    token = s.substr(0, dash_pos);
    range_start = convert_to_int(token);
    s.erase(0, dash_pos + delimiter.length());

    range_end = convert_to_int(s);
    check_port_range(range_start);
    check_port_range(range_end);
    if (range_start > range_end)
        Logger::error_exit("Error in port range definition, start number is bigger than the end one");

    for (i = range_start; i <= range_end; i++) {
        v.insert(v.end(), i);
    }

    return v;
}

bool ArgParser::contains_char(string& s, string& delimiter) {
    return s.find(delimiter) != string::npos;
}

int ArgParser::convert_to_int(string &s) {
    int port;
    size_t index = 0;

    try {
        port = stoi(s, &index);
    } catch (const invalid_argument& ia) {
        Logger::error_exit("Exception occured when trying to convert port input into number");
    }

    if (index != s.length()) {
        Logger::error_exit("Port number contains some unexpected characters");
    }

    check_port_range(port);
    return port;
}

void ArgParser::print_tcp_ports() {
    cout << "\tTCP ports to be scanned: ";
    for (vector<int>::const_iterator i=(this->tcpPorts).begin(); i !=(this->tcpPorts).end(); ++i)
        cout << *i << ' ';
    cout << "\n";
}

void ArgParser::print_udp_ports() {
    cout << "\tUDP ports to be scanned: ";
    for (vector<int>::const_iterator i=(this->udpPorts).begin(); i !=(this->udpPorts).end(); ++i)
        cout << *i << ' ';
    cout << "\n";
}

bool ArgParser::is_range_valid(string &s) {
    size_t contain;
    int i = 0;
    int dashcnt = 0;

    while ((contain = s.find(DASH,i)) != string::npos){
        dashcnt++;
        i = contain + 1;
    }
    return dashcnt == 1 ? true : false;
}

void ArgParser::check_port_range(int port) {
    if (port < 0 || port > 65535) {
        Logger::error_exit("Port number is lower than 1 or greater than 65535");
    }
}

vector<int> &ArgParser::getTcpPorts() {
    return tcpPorts;
}

vector<int> &ArgParser::getUdpPorts() {
    return udpPorts;
}

string &ArgParser::getHost() {
    return host;
}

string &ArgParser::getIface_name() {
    return iface_name;
}

