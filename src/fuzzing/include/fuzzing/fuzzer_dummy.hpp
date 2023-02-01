#ifndef FUZZING_FUZZER_DUMMY_HPP_INCLUDED
#   define FUZZING_FUZZER_DUMMY_HPP_INCLUDED

#   include <fuzzing/fuzzer_base.hpp>

namespace  fuzzing {


struct  fuzzer_dummy : public fuzzer_base
{
    explicit fuzzer_dummy(termination_info const&  info);
protected:
    void  on_execution_begin() override;
    void  on_execution_end() override;
};


}

#endif
