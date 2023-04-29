#include <connection/client_configuration.hpp>


namespace connection {

void client_configuration::save(message& dest) const {
    dest << required_shared_memory_size;
    dest << timeout_ms;
}

void client_configuration::load(message& src) {
    src >> required_shared_memory_size;
    src >> timeout_ms;
}
    
}