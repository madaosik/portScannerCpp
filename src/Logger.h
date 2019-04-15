//
// Created by Adam Láníček on 2019-04-13.
//

#ifndef IPK_SCAN_LOGGER_H
#define IPK_SCAN_LOGGER_H

#include <string>
#include <iostream>

using namespace std;

class Logger {
    public:
        static void change_debug_status(bool debug);
        static void error_exit(const string& error_msg);
        static void log_warning(const string& warning_msg);
        static void log_status(const string& status_msg, const string& var_content);
    private:
        static bool is_debug();
        static bool debug_flag;
};


#endif //IPK_SCAN_LOGGER_H
