#include <fuzzing/fuzzer_dummy.hpp>

namespace  fuzzing {


fuzzer_dummy::fuzzer_dummy(termination_info const&  info)
    : fuzzer_base(info)
{}


void  fuzzer_dummy::on_execution_begin()
{
    // Nothing to do.
}


void  fuzzer_dummy::on_execution_end()
{
    // Nothing to do.
}


}
