#ifndef FUZZING_DUMP_TESTCOMP_HPP_INCLUDED
#   define FUZZING_DUMP_TESTCOMP_HPP_INCLUDED

#   include <fuzzing/analysis_outcomes.hpp>
#   include <fuzzing/termination_info.hpp>
#   include <string>
#   include <iosfwd>
#   include <filesystem>

namespace  fuzzing {

void save_testcomp_metadata(std::ostream&  ostr, const std::string& version, const std::string& program_file);
void save_testcomp_test_inputs(std::ostream& ostr, const execution_record& trace);
void save_testcomp_test(std::ostream& ostr, const execution_record& trace);
void save_testcomp_output(
    std::filesystem::path const& output_dir,
    std::vector<execution_record> const&  traces_forming_coverage,
    const std::string& test_name_prefix,
    const std::string& version,
    const std::string& program_file
    );

}

#endif
