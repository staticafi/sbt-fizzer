#include <iomodels/stdin_replay_bits_then_repeat_zero.hpp>
#include <iomodels/ioexceptions.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <iostream>

namespace  iomodels {


stdin_replay_bits_then_repeat_zero::stdin_replay_bits_then_repeat_zero(bit_count_type const  max_bits_)
    : stdin_base{ max_bits_ }
    , cursor(0U)
    , bits()
    , counts()
{}


void  stdin_replay_bits_then_repeat_zero::clear()
{
    cursor = 0U;
    bits.clear();
    counts.clear();
}


void  stdin_replay_bits_then_repeat_zero::save(connection::message&  ostr) const
{
    INVARIANT(bits.size() <= max_bits());

    vecu8  bytes;
    bits_to_bytes(bits, bytes);
    ostr << (natural_16_bit)bytes.size();
    for (natural_8_bit  byte : bytes)
        ostr << byte;

    ostr << (natural_16_bit)counts.size();
    for (natural_8_bit  cnt : counts)
        ostr << cnt;
}


void  stdin_replay_bits_then_repeat_zero::load(connection::message&  istr)
{
    natural_16_bit  num_bytes;
    istr >> num_bytes;
    vecu8  bytes(num_bytes, 0);
    for (natural_16_bit  i = 0U; i < num_bytes; ++i)
        istr >> bytes.at(i);
    bytes_to_bits(bytes, bits);

    ASSUMPTION(bits.size() <= max_bits());

    natural_16_bit  num_counts;
    istr >> num_counts;
    counts.resize(num_counts);
    for (natural_16_bit  i = 0U; i < num_counts; ++i)
        istr >> counts.at(i);
}


void  stdin_replay_bits_then_repeat_zero::read(location_id const  id, natural_8_bit* ptr, natural_8_bit const  count)
{
    for (natural_8_bit  j = 0U; j != count; ++j)
    {
        natural_8_bit  value = 0U;
        for (natural_8_bit  i = 0; i != 8; ++i)
        {
            if (cursor >= max_bits())
                throw boundary_condition_violation("The max stdin bits exceeded.");

            if (cursor == (natural_16_bit)bits.size())
                bits.push_back(false); // Here we generate a sequence 000000... => we produce a sequence of bytes 0,0,0,...
            value |= (natural_8_bit)((bits.at(cursor) ? 1U : 0U) << (7U - i));
            ++cursor;
        }
        ptr[j] = value;
    }
    counts.push_back(8U * count);

    /*
    // WARNING: If the server sends input s.t. "bits.size() % 8 != 0", then this
    //          implementation will skip the last "bits.size() - 8 * (bits.size() / 8)" bits.

    natural_8_bit to_replay = (natural_8_bit)std::min((bits.size() - cursor) / 8, (std::size_t)count);
    for (natural_8_bit  j = 0U; j != to_replay; ++j)
    {
        ptr[j] = 0;
        for (natural_8_bit  i = 0; i != 8; ++i)
        {
            ptr[j] |= (natural_8_bit)((bits.at(cursor) ? 1U : 0U) << (7U - i));
            ++cursor;
        }
    }

    natural_8_bit leftover = count - to_replay;
    memset((void*) (ptr + to_replay), 85, leftover);
    if (bits.size() + 8 * leftover <= get_max_bits())
    {
        for (natural_8_bit  j = 0; j != leftover; ++j)
        {
            for (natural_8_bit  i = 0; i != 8; ++i)
            {
                bits.push_back(ptr[j] & (1 << (7U - i)));
                ++cursor;
            }
        }
        
        counts.push_back(8U * count);
    }
    */
}


}