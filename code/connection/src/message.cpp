#include <connection/message.hpp>
#include <utility/endian.hpp>
#include <utility/assumptions.hpp>

namespace  connection {

message_header::message_header() {}
message_header::message_header(message_type type):
    type(type)
{}


message::message():
    bytes()
{}


message::message(message_type type):
    header{type},
    bytes()
{}


message_type message::type() {
    return header.type;
}

natural_32_bit message::size() {
    return header.size - cursor;
}


void  message::clear()
{
    bytes.clear();
    cursor = 0U;
    header.type = message_type::not_set;
    header.size = 0;
}


bool  message::empty() {
    return bytes.empty();
}


}
