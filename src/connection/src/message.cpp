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
    header.size = 0;
}

bool  message::empty() {
    return bytes.empty();
}

bool message::can_accept_bytes(size_t n) const {
    return true;
}

bool message::can_deliver_bytes(size_t n) const {
    return cursor + n <= bytes.size();
}

void message::accept_bytes(const void* src, size_t n) {
    std::size_t old_size = bytes.size();
    bytes.resize(old_size + n);
    memcpy(bytes.data() + old_size, src, n);
    header.size += (natural_32_bit)n;
}

void message::deliver_bytes(void* dest, size_t n) {
    memcpy(dest, bytes.data() + cursor, n);
    cursor += (natural_32_bit)n;
}

message& message::operator<<(const std::string& src) {
    *this << (natural_32_bit) src.size();
    accept_bytes(src.data(), (natural_32_bit) src.size());
    return *this;
}

message& message::operator>>(std::string& dest) {
    natural_32_bit size;
    *this >> size;
    dest.resize(size);
    deliver_bytes(dest.data(), (size));
    return *this;
}

bool message::exhausted() const {
    return cursor >= bytes.size();
}


}