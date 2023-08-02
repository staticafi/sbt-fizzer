#ifndef FUZZING_DUMP_NATIVE_HPP_INCLUDED
#   define FUZZING_DUMP_NATIVE_HPP_INCLUDED

#   include <fuzzing/execution_record.hpp>
#   include <iosfwd>

namespace  fuzzing {


void  save_native_test(std::ostream&  ostr, execution_record const&  record);


}

#endif
