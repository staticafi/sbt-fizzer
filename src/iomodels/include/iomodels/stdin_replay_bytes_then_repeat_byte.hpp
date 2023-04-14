#ifndef IOMODELS_STDIN_REPLAY_BYTES_THEN_REPEAT_BYTE_HPP_INCLUDED
#   define IOMODELS_STDIN_REPLAY_BYTES_THEN_REPEAT_BYTE_HPP_INCLUDED

#   include <iomodels/stdin_base.hpp>
#   include <utility/math.hpp>

namespace  iomodels {


struct stdin_replay_bytes_then_repeat_byte : public stdin_base
{
    stdin_replay_bytes_then_repeat_byte(byte_count_type  max_bytes_, natural_8_bit repeat_byte);

    void  clear() override;
    void  save(connection::message&  ostr) const override;
    void  load(connection::message&  istr) override;
    void  read(location_id  id, natural_8_bit*  ptr, natural_8_bit  count) override;

    vecu8 const&  get_bytes() const override { return bytes; }
    vecu8 const&  get_counts() const override { return counts; }
    byte_count_type  num_bytes_read() const override { return cursor; }

    void  set_bytes(vecu8 const&  bytes_) override { bytes = bytes_; }

private:
    byte_count_type  cursor;
    vecu8  bytes;
    vecu8  counts;
    natural_8_bit repeat_byte;
};


}

#endif
