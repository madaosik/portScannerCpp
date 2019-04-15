//
// Created by Adam Láníček on 2019-04-13.
//

#include "Logger.h"

bool Logger::debug_flag = false;

void Logger::change_debug_status(bool debug) {
    Logger::debug_flag = debug;
}

bool Logger::is_debug() {
    return Logger::debug_flag ? true : false;
}

void Logger::error_exit(const string& error_msg) {
    cerr << "\tERROR: " << error_msg << ". Terminating...\n";
    exit(1);
}

void Logger::log_warning(const string& warning_msg) {
    if (is_debug()) {
        cout << "\tWARNING: " << warning_msg << ".\n";
    }
}

void Logger::log_status(const string& status_msg, const string& var_content) {
    if (is_debug()) {
        cout << "\tINFO: " << status_msg << ": " << var_content << "\n";
    }
}