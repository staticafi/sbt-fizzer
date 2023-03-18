#ifndef IOMODELS_STDIN_REPLAY_BITS_THEN_REPEAT_ZERO_HPP_INCLUDED
#   define IOMODELS_STDIN_REPLAY_BITS_THEN_REPEAT_ZERO_HPP_INCLUDED

#   include <iomodels/stdin_base.hpp>
#   include <utility/math.hpp>

namespace  iomodels {


struct stdin_replay_bits_then_repeat_zero : public stdin_base
{
    stdin_replay_bits_then_repeat_zero(bit_count_type  max_bits_);

    void  clear() override;
    void  save(connection::message&  ostr) const override;
    void  load(connection::message&  istr) override;
    void  read(location_id const  id, natural_8_bit* ptr, natural_8_bit const  count) override;

    vecb const&  get_bits() const override { return bits; }
    vecu8 const&  get_counts() const override { return counts; }
    bit_count_type  num_bits_read() const override { return cursor; }

    void  set_bits(vecb const&  bits_) override { bits = bits_; }

private:
    bit_count_type  cursor;
    vecb  bits;
    vecu8  counts;
};


}

#endif
