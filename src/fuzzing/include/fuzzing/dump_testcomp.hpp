#ifndef FUZZING_DUMP_TESTCOMP_HPP_INCLUDED
#   define FUZZING_DUMP_TESTCOMP_HPP_INCLUDED

#   include <fuzzing/execution_record.hpp>
#   include <iosfwd>

namespace  fuzzing {


void save_testcomp_test(std::ostream& ostr, const execution_record& trace);


}

#endif
