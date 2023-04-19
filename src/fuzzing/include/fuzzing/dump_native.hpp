#ifndef FUZZING_DUMP_NATIVE_HPP_INCLUDED
#   define FUZZING_DUMP_NATIVE_HPP_INCLUDED

#   include <fuzzing/analysis_outcomes.hpp>
#   include <string>
#   include <iosfwd>
#   include <filesystem>

namespace  fuzzing {


void  save_native_test(std::ostream&  ostr, execution_record const&  record);

void  save_native_output(
        std::filesystem::path const&  output_dir,
        std::vector<execution_record> const&  records,
        std::string const&  test_name_prefix
        );


}

#endif
