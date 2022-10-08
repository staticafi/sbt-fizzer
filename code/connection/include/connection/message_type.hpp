#ifndef CONNECTION_MESSAGE_TYPE_HPP_INCLUDED
#   define CONNECTION_MESSAGE_TYPE_HPP_INCLUDED

#   include <cstdint>

namespace connection {


enum class message_type: uint32_t {
    not_set,
    input_for_client,
    results_from_client_normal,
    results_from_client_max_trace_reached,
    results_from_client_abort_reached,
    results_from_client_error_reached
};

}

#endif