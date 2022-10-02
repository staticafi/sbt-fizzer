#include <connection/medium.hpp>
#include <utility/endian.hpp>
#include <utility/assumptions.hpp>

namespace  connection {


medium::medium():
    bytes(),
    cursor(0),
    tmp_body_size(0)
{}

void  medium::clear()
{
    bytes.clear();
    cursor = 0U;
}


bool  medium::empty() {
    return bytes.empty();
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


std::size_t medium::receive_bytes(boost::asio::ip::tcp::socket& socket, boost::system::error_code& ec) {
    boost::asio::read(socket, boost::asio::buffer(&tmp_body_size, sizeof(natural_32_bit)), ec);
    if (ec) {
        return 0;
    }
    bytes.resize(tmp_body_size);
    return boost::asio::read(socket, boost::asio::buffer(bytes), ec);
}

std::size_t medium::send_bytes(boost::asio::ip::tcp::socket& socket, boost::system::error_code& ec) {
    tmp_body_size = bytes.size();
    boost::asio::write(socket, boost::asio::buffer(&tmp_body_size, sizeof(natural_32_bit)), ec);
    if (ec) {
        return 0;
    }
    return boost::asio::write(socket, boost::asio::buffer(bytes), ec);
}


}
