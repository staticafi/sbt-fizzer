#ifndef IOMODELS_STDIN_REPLAY_BITS_THEN_REPEAT_85_HPP_INCLUDED
#   define IOMODELS_STDIN_REPLAY_BITS_THEN_REPEAT_85_HPP_INCLUDED

#   include <iomodels/stdin_base.hpp>
#   include <utility/math.hpp>

namespace  iomodels {


struct stdin_replay_bits_then_repeat_85 : public stdin_base
{
    stdin_replay_bits_then_repeat_85();

    void  clear() override;
    void  save(connection::message&  ostr) const override;
    void  load(connection::message&  istr) override;
    void  read(location_id const  id, natural_8_bit* ptr, natural_8_bit const  count) override;

    vecb const&  get_bits() const override { return bits; }
    vecu8 const&  get_counts() const override { return counts; }

    vecb&  bits_ref() { return bits; }

private:
    natural_16_bit  cursor;
    vecb  bits;
    vecu8  counts;
};


}

#endif
