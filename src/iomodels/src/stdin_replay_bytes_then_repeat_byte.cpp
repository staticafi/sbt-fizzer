#include <iomodels/stdin_replay_bytes_then_repeat_byte.hpp>
#include <iomodels/ioexceptions.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <iostream>

namespace  iomodels {


stdin_replay_bytes_then_repeat_byte::stdin_replay_bytes_then_repeat_byte(byte_count_type const  max_bytes_, natural_8_bit repeat_byte)
    : stdin_base{ max_bytes_ }
    , cursor(0U)
    , bytes()
    , counts()
    , repeat_byte(repeat_byte)
{}


void  stdin_replay_bytes_then_repeat_byte::clear()
{
    cursor = 0U;
    bytes.clear();
    counts.clear();
}


void  stdin_replay_bytes_then_repeat_byte::save(connection::message& ostr) const
{
    INVARIANT(bytes.size() <= max_bytes());

    ostr << (natural_16_bit)bytes.size();
    ostr.load(bytes.data(),(natural_16_bit)bytes.size());

    ostr << (natural_16_bit)counts.size();
    ostr.load(counts.data(), (natural_16_bit)counts.size());
}


void  stdin_replay_bytes_then_repeat_byte::load(connection::message&  istr)
{
    natural_16_bit  num_bytes;
    istr >> num_bytes;
    bytes.resize(num_bytes);
    istr.save(bytes.data(), num_bytes);

    ASSUMPTION(bytes.size() <= max_bytes());

    natural_16_bit  num_counts;
    istr >> num_counts;
    counts.resize(num_counts);
    istr.save(counts.data(), num_counts);
}


void  stdin_replay_bytes_then_repeat_byte::read(location_id  id, natural_8_bit*  ptr, natural_8_bit  count)
{
    if (cursor + count > max_bytes()) {
        throw boundary_condition_violation("The max stdin bytes exceeded.");
    }
    if (cursor + count > bytes.size()) {
        bytes.resize(cursor + count, repeat_byte);
    }
    memcpy(ptr, bytes.data() + cursor, count);
    cursor += count;
    counts.push_back(count);
}


}