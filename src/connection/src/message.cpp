#include <connection/message.hpp>
#include <utility/endian.hpp>
#include <utility/assumptions.hpp>

namespace  connection {


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

void message::load(const void* src, size_t n) {
    std::size_t old_size = bytes.size();
    bytes.resize(old_size + n);
    memcpy(bytes.data() + old_size, src, n);
    header.size += n;
}

void message::save(void* dest, size_t n) {
    ASSUMPTION(cursor + n <= bytes.size());
    memcpy(dest, bytes.data() + cursor, n);
    cursor += n;
}


bool message::exhausted() const {
    return cursor >= bytes.size();
}


}