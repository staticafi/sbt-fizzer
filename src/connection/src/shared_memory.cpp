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
    std::size_t size = region.get_size();
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

bool shared_memory::can_accept_bytes(std::size_t const n) const {
    return memory != nullptr && get_size() >= *saved + n;
}

bool shared_memory::can_deliver_bytes(std::size_t const n) const {
    return memory != nullptr && *saved >= cursor + n;
}

void shared_memory::accept_bytes(const void* src, std::size_t n) {
    memcpy(memory + *saved, src, n);
    *saved += (natural_32_bit)n;
}

void shared_memory::deliver_bytes(void* dest, std::size_t n) {
    memcpy(dest, memory + cursor, n);
    cursor += (natural_32_bit)n;
}

shared_memory& shared_memory::operator<<(const std::string& src) {
    *this << (natural_32_bit) src.size();
    accept_bytes(src.data(), (natural_32_bit) src.size());
    return *this;
}

shared_memory& shared_memory::operator>>(std::string& dest) {
    natural_32_bit size;
    *this >> size;
    dest.resize(size);
    deliver_bytes(dest.data(), (size));
    return *this;
}

std::optional<target_termination> shared_memory::get_termination() const {
    data_record_id id = static_cast<data_record_id>(*memory);
    if (id != data_record_id::termination) {
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


void shared_memory::accept_bytes(message& src) {
    std::size_t src_size = src.size();
    src.deliver_bytes(memory, src_size);
    *saved += (natural_32_bit)src_size;
}


void shared_memory::deliver_bytes(message& dest) {
    dest.accept_bytes(memory, *saved);
    cursor += *saved;
}


bool shared_memory::exhausted() const {
    return cursor >= *saved;
}


}