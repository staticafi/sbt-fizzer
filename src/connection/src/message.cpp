#include <connection/message.hpp>
#include <utility/endian.hpp>
#include <utility/assumptions.hpp>

namespace  connection {

message_header::message_header() {}


message::message():
    bytes()
{}


natural_32_bit message::size() {
    return header.size - cursor;
}


void  message::clear()
{
    bytes.clear();
    cursor = 0U;
    header.type = 0;
    header.size = 0;
}


bool  message::empty() {
    return bytes.empty();
}


}
