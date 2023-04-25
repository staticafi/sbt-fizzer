#ifndef FUZZING_DUMP_HPP_INCLUDED
#   define FUZZING_DUMP_HPP_INCLUDED

#   include <fuzzing/analysis_outcomes.hpp>
#   include <fuzzing/termination_info.hpp>
#   include <iomodels/iomanager.hpp>
#   include <string>
#   include <iosfwd>
#   include <filesystem>

namespace  fuzzing {


void  print_fuzzing_configuration(
        std::ostream&  ostr,
        std::string const&  benchmark,
        iomodels::iomanager::configuration const&  ioconfig,
        termination_info const&  terminator
        );

void  print_analysis_outcomes(std::ostream&  ostr,
        analysis_outcomes const&  results,
        bool  dump_traces = false,
        bool  dump_analysis_statistics = false);

void  print_execution_record(
        std::ostream&  ostr,
        execution_record const&  record,
        bool  dump_chunks,
        std::string const&  shift = ""
        );

void  save_execution_records_to_directory(
        std::filesystem::path const&  output_dir,
        std::vector<execution_record> const&  records,
        bool  dump_chunks,
        std::string const&  test_name_prefix = ""
        );

void  save_debug_data_to_directory(
        std::filesystem::path const&  output_dir,
        std::string const&  name_prefix,
        std::unordered_map<std::string, std::string> const&  data
        );


}

#endif
