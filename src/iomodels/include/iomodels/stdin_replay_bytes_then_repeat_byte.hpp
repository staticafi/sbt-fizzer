#ifndef IOMODELS_STDIN_REPLAY_BYTES_THEN_REPEAT_BYTE_HPP_INCLUDED
#   define IOMODELS_STDIN_REPLAY_BYTES_THEN_REPEAT_BYTE_HPP_INCLUDED

#   include <iomodels/stdin_base.hpp>
#   include <utility/math.hpp>

namespace  iomodels {


struct stdin_replay_bytes_then_repeat_byte : public stdin_base
{
    stdin_replay_bytes_then_repeat_byte(byte_count_type  max_bytes_, natural_8_bit repeat_byte);

    void  clear() override;
    void  save(connection::message&  dest) const override;
    void  save(connection::shared_memory&  dest) const override;
    void  load(connection::message&  src) override;
    void  load(connection::shared_memory&  src) override;
    void  load_record(connection::message&  src) override;
    void  load_record(connection::shared_memory&  src) override;
    size_t max_flattened_size() const override;
    void  read(natural_8_bit*  ptr, type_of_input_bits  type, connection::shared_memory& dest) override;

    vecu8 const&  get_bytes() const override { return bytes; }
    input_types_vector const&  get_types() const override { return types; }
    byte_count_type  num_bytes_read() const override { return cursor; }

    void  set_bytes(vecu8 const&  bytes_) override { bytes = bytes_; }

private:
    template <typename Medium>
    void  load_(Medium& src);
    template <typename Medium>
    void  save_(Medium& dest) const;
    template <typename Medium>
    void  load_record_(Medium& src);

    byte_count_type  cursor;
    vecu8  bytes;
    input_types_vector  types;
    natural_8_bit  repeat_byte;
};


}

#endif
