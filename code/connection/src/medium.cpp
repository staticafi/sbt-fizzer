#include <connection/medium.hpp>
#include <utility/endian.hpp>
#include <utility/assumptions.hpp>

namespace  connection {

void  medium::clear()
{
    bytes.clear();
    cursor = 0U;
}

void  medium::unblock() {
    std::unique_lock<std::mutex> ul(block_mux);
    block.notify_one();
}

void  medium::wait() {
    while (bytes.size() <= cursor) {
        std::unique_lock<std::mutex> lock(block_mux);
        block.wait(lock);
    }
}

void  medium::save_bytes(natural_8_bit const*  ptr, natural_32_bit const  count)
{
    if (is_this_little_endian_machine())
        for (natural_32_bit  i = 0U; i < count; ++i)
            bytes.push_back(ptr[i]);
    else
        for (natural_32_bit  i = 1U; i <= count; ++i)
            bytes.push_back(ptr[count - i]);
}


void  medium::load_bytes(natural_8_bit*  ptr, natural_32_bit const  count)
{
    ASSUMPTION(cursor + count <= (natural_16_bit)bytes.size());
    if (is_this_little_endian_machine())
        for (natural_32_bit  i = 0U; i < count; ++i, ++cursor)
            ptr[i] = bytes.at(cursor);
    else
        for (natural_32_bit  i = 1U; i <= count; ++i, ++cursor)
            ptr[count - i] = bytes.at(cursor);
}


}
