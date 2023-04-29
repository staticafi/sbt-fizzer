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
    header.size += (natural_32_bit)n;
}

void message::save(void* dest, size_t n) {
    ASSUMPTION(cursor + n <= bytes.size());
    memcpy(dest, bytes.data() + cursor, n);
    cursor += (natural_32_bit)n;
}

message& message::operator<<(const std::string& src) {
    *this << (natural_32_bit) src.size();
    load(src.data(), (natural_32_bit) src.size());
    return *this;
}

message& message::operator>>(std::string& dest) {
    natural_32_bit size;
    *this >> size;
    dest.resize(size);
    save(dest.data(), (size));
    return *this;
}

bool message::exhausted() const {
    return cursor >= bytes.size();
}


}