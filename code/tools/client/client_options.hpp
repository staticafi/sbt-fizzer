#ifndef CLIENT_CLIENT_OPTIONS_HPP_INCLUDED
#define CLIENT_CLIENT_OPTIONS_HPP_INCLUDED

#include <utility/basic_numeric_types.hpp>
#include <utility/math.hpp>
#include <vector>

struct client_options {
    vecu8 input_bytes;

    static client_options& instance();
    int parse_client_options(int argc, char *argv[]);
};

#endif