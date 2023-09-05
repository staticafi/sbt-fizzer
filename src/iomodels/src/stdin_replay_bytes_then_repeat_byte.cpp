#include <iomodels/stdin_replay_bytes_then_repeat_byte.hpp>
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
    , types()
    , repeat_byte(repeat_byte)
{}


void  stdin_replay_bytes_then_repeat_byte::clear()
{
    cursor = 0U;
    bytes.clear();
    types.clear();
}

template <typename Medium>
void  stdin_replay_bytes_then_repeat_byte::save_(Medium& dest) const
{
    INVARIANT(bytes.size() <= max_bytes());

    dest << (byte_count_type)bytes.size();
    dest.accept_bytes(bytes.data(),(byte_count_type)bytes.size());

    dest << (byte_count_type)types.size();
    dest.accept_bytes(types.data(), (byte_count_type)types.size());
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
    byte_count_type  num_bytes;
    src >> num_bytes;
    bytes.resize(num_bytes);
    src.deliver_bytes(bytes.data(), num_bytes);

    ASSUMPTION(bytes.size() <= max_bytes());

    byte_count_type  num_types;
    src >> num_types;
    types.resize(num_types);
    src.deliver_bytes(types.data(), num_types);
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
bool  stdin_replay_bytes_then_repeat_byte::load_record_(Medium& src) {
    if (!src.can_deliver_bytes(1))
        return false;
    natural_8_bit type_id;
    src >> type_id;
    type_of_input_bits const type = from_id(type_id);
    natural_8_bit const count = num_bytes(type);
    if (!src.can_deliver_bytes(count))
        return false;
    types.push_back(type);
    size_t old_size = bytes.size();
    bytes.resize(old_size + count);
    src.deliver_bytes(bytes.data() + old_size, count);
    return true;
}


template bool stdin_replay_bytes_then_repeat_byte::load_record_(shared_memory&);
template bool stdin_replay_bytes_then_repeat_byte::load_record_(message&);


bool  stdin_replay_bytes_then_repeat_byte::load_record(message&  src) {
    return load_record_(src);
}

bool  stdin_replay_bytes_then_repeat_byte::load_record(shared_memory&  src) {
    return load_record_(src);
}


std::size_t stdin_replay_bytes_then_repeat_byte::min_flattened_size() const {
    return sizeof(input_types_vector::value_type) + 1;
}



void  stdin_replay_bytes_then_repeat_byte::read(natural_8_bit*  ptr, 
                                                type_of_input_bits const type,
                                                shared_memory& dest)
{
    natural_8_bit const count = num_bytes(type);
    if (cursor + count > max_bytes()) {
        dest.set_termination(target_termination::boundary_condition_violation);
        exit(0);
    }
    if (!dest.can_accept_bytes(count + 2)) {
        dest.set_termination(target_termination::medium_overflow);
        exit(0);
    }
    if (cursor + count > bytes.size()) {
        bytes.resize(cursor + count, repeat_byte);
    }
    memcpy(ptr, bytes.data() + cursor, count);
    dest << data_record_id::stdin_bytes << to_id(type);
    dest.accept_bytes(bytes.data() + cursor, count);
    cursor += count;
    types.push_back(type);
}


}
