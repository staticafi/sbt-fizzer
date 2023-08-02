#ifndef FUZZING_DUMP_TESTCOMP_HPP_INCLUDED
#   define FUZZING_DUMP_TESTCOMP_HPP_INCLUDED

#   include <fuzzing/execution_record.hpp>
#   include <string>
#   include <iosfwd>
#   include <filesystem>

namespace  fuzzing {

void save_testcomp_metadata(std::ostream&  ostr, const std::string& version, const std::string& program_file);
void save_testcomp_test_inputs(std::ostream& ostr, const execution_record& trace);
void save_testcomp_test(std::ostream& ostr, const execution_record& trace);

}

#endif
