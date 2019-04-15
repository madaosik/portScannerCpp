//
// Created by Adam Láníček on 2019-04-14.
//

#ifndef IPK_SCAN_SCANNER_H
#define IPK_SCAN_SCANNER_H

#include <vector>
#include <map>
#include <string>

#include <arpa/inet.h>
#include <netdb.h>

#include "Logger.h"

#define MAX_LEN 50

enum State {OPEN,CLOSED,FILTERED};

using namespace std;

class Scanner {
    public:
        Scanner(vector<int> &port_vector);
        void run_scan();
        virtual State scan_port(int port) = 0;
        void set_host_ip(string& host);
        void print_header();
        void print_results(string protocol);
    private:
        bool validate_ip(char *host);
        string host_name;
        char host_ip[16];
    protected:
        map<State,string> state_map;
        map<int,State> results_map;
        vector<int>& ports;
};


#endif //IPK_SCAN_SCANNER_H
