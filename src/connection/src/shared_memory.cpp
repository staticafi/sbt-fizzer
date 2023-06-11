#include <connection/shared_memory.hpp>
#include <iomodels/models_map.hpp>
#include <iomodels/configuration.hpp>
#include <instrumentation/data_record_id.hpp>

namespace bip = boost::interprocess;
using namespace instrumentation;

namespace  connection {


void shared_memory::open_or_create() {
    shm = bip::shared_memory_object(bip::open_or_create, segment_name, bip::read_write);
}


natural_32_bit shared_memory::get_size() const {
    size_t size = region.get_size();
    if (size != 0) {
        return (natural_32_bit)(size - sizeof(*saved));
    }
    return (natural_32_bit)size;
}


void shared_memory::set_size(natural_32_bit size) {
    shm.truncate(size + sizeof(*saved));
}

void shared_memory::clear() {
    cursor = 0;
    *saved = 0;
}


void shared_memory::map_region() {
    region = bip::mapped_region(shm, bip::read_write);
    cursor = 0;
    saved = static_cast<natural_32_bit*>(region.get_address());
    memory = static_cast<natural_8_bit*>(region.get_address()) + sizeof(*saved);
}   

void shared_memory::remove() {
    bip::shared_memory_object::remove(segment_name);
}

void shared_memory::load(const void* src, size_t n) {
    ASSUMPTION(memory != nullptr);
    ASSUMPTION(*saved + n <= get_size());
    memcpy(memory + *saved, src, n);
    *saved += (natural_32_bit)n;
}

void shared_memory::save(void* dest, size_t n) {
    ASSUMPTION(memory != nullptr);
    ASSUMPTION(cursor + n <= *saved);
    memcpy(dest, memory + cursor, n);
    cursor += (natural_32_bit)n;
}

shared_memory& shared_memory::operator<<(const std::string& src) {
    *this << (natural_32_bit) src.size();
    load(src.data(), (natural_32_bit) src.size());
    return *this;
}

shared_memory& shared_memory::operator>>(std::string& dest) {
    natural_32_bit size;
    *this >> size;
    dest.resize(size);
    save(dest.data(), (size));
    return *this;
}

std::optional<target_termination> shared_memory::get_termination() const {
    data_record_id id = static_cast<data_record_id>(*memory);
    if (id == data_record_id::invalid || id != data_record_id::termination) {
        return std::nullopt;
    }

    target_termination termination = static_cast<target_termination>(*(memory + 1));
    if (!valid_termination(termination)) {
        return std::nullopt;
    }

    return termination;
}

void shared_memory::set_termination(target_termination termination) {
    *memory = static_cast<natural_8_bit>(data_record_id::termination);
    *(memory + 1) = static_cast<natural_8_bit>(termination);
}


void shared_memory::save(message& dest) {
    dest.load(memory, *saved);
    cursor += *saved;
}


void shared_memory::load(message& src) {
    size_t src_size = src.size();
    src.save(memory, src_size);
    *saved += (natural_32_bit)src_size;
}


bool shared_memory::exhausted() const {
    return cursor >= *saved;
}


}