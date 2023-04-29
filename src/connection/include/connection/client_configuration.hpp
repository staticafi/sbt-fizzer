#ifndef CONNECTION_CLIENT_CONFIGURATION_HPP_INCLUDED
#   define CONNECTION_CLIENT_CONFIGURATION_HPP_INCLUDED


#   include <utility/basic_numeric_types.hpp>
#   include <connection/message.hpp>

namespace connection {
    
struct client_configuration {
    void save(message& dest) const;
    void load(message& src);

    natural_32_bit required_shared_memory_size;
    natural_32_bit timeout_ms;
};

}

#endif