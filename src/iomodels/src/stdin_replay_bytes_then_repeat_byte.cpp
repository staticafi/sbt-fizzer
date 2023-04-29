#include <iomodels/stdin_replay_bytes_then_repeat_byte.hpp>
#include <iomodels/ioexceptions.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <instrumentation/data_record_id.hpp>
#include <instrumentation/target_termination.hpp>

using namespace connection;
using namespace instrumentation;

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

template <typename Medium>
void  stdin_replay_bytes_then_repeat_byte::save_(Medium& dest) const
{
    INVARIANT(bytes.size() <= max_bytes());

    dest << (natural_16_bit)bytes.size();
    dest.load(bytes.data(),(natural_16_bit)bytes.size());

    dest << (natural_16_bit)counts.size();
    dest.load(counts.data(), (natural_16_bit)counts.size());
}

template void stdin_replay_bytes_then_repeat_byte::save_(shared_memory&) const;
template void stdin_replay_bytes_then_repeat_byte::save_(message&) const;


void  stdin_replay_bytes_then_repeat_byte::save(message& dest) const
{
    save_(dest);
}

void  stdin_replay_bytes_then_repeat_byte::save(shared_memory& dest) const
{
    save_(dest);    
}

template <typename Medium>
void  stdin_replay_bytes_then_repeat_byte::load_(Medium&  src)
{
    natural_16_bit  num_bytes;
    src >> num_bytes;
    bytes.resize(num_bytes);
    src.save(bytes.data(), num_bytes);

    ASSUMPTION(bytes.size() <= max_bytes());

    natural_16_bit  num_counts;
    src >> num_counts;
    counts.resize(num_counts);
    src.save(counts.data(), num_counts);
}

template void stdin_replay_bytes_then_repeat_byte::load_(shared_memory&);
template void stdin_replay_bytes_then_repeat_byte::load_(message&);


void  stdin_replay_bytes_then_repeat_byte::load(message&  src)
{
    load_(src);
}

void  stdin_replay_bytes_then_repeat_byte::load(shared_memory&  src)
{
    load_(src);
}


template <typename Medium>
void  stdin_replay_bytes_then_repeat_byte::load_record_(Medium& src) {
    natural_8_bit count;
    src >> count;
    counts.push_back(count);
    size_t old_size = bytes.size();
    bytes.resize(old_size + count);
    src.save(bytes.data() + old_size, count);
}


template void stdin_replay_bytes_then_repeat_byte::load_record_(shared_memory&);
template void stdin_replay_bytes_then_repeat_byte::load_record_(message&);


void  stdin_replay_bytes_then_repeat_byte::load_record(connection::message&  src) {
    load_record_(src);
}

void  stdin_replay_bytes_then_repeat_byte::load_record(connection::shared_memory&  src) {
    load_record_(src);
}


size_t stdin_replay_bytes_then_repeat_byte::max_flattened_size() const {
    return sizeof(counts[0]) * max_bytes() + max_bytes();
}



void  stdin_replay_bytes_then_repeat_byte::read(natural_8_bit*  ptr, 
                                                natural_8_bit  count,
                                                shared_memory& dest)
{
    if (cursor + count > max_bytes()) {
        dest.set_termination(target_termination::stdin_max_bytes_reached);
        exit(0);
    }
    if (cursor + count > bytes.size()) {
        bytes.resize(cursor + count, repeat_byte);
    }
    memcpy(ptr, bytes.data() + cursor, count);
    dest << data_record_id::stdin_bytes << count;
    dest.load(bytes.data() + cursor, count);
    cursor += count;
    counts.push_back(count);
}


}
