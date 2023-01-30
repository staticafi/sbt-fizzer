#ifndef FUZZING_DUMP_HPP_INCLUDED
#   define FUZZING_DUMP_HPP_INCLUDED

#   include <fuzzing/analysis_outcomes.hpp>
#   include <fuzzing/termination_info.hpp>
#   include <string>
#   include <iosfwd>
#   include <filesystem>

namespace  fuzzing {


void  print_fuzzing_configuration(
        std::ostream&  ostr,
        std::string const&  fuzzer_name,
        std::string const&  benchmark_name,
        termination_info const&  info,
        std::size_t  max_trace_size,
        std::size_t  max_stdin_bits
        );

void  print_analysis_outcomes(std::ostream&  ostr, analysis_outcomes const&  results, bool const  dump_traces = false);

void  print_trace_with_coverage_info(
        std::ostream&  ostr,
        trace_with_coverage_info const&  trace,
        bool  dump_coverage_info,
        bool  dump_chunks,
        std::string const&  shift = ""
        );

void  save_traces_with_coverage_infos_to_directory(
        std::filesystem::path const&  output_dir,
        std::vector<trace_with_coverage_info> const&  traces_forming_coverage,
        bool  dump_coverage_info,
        bool  dump_chunks,
        std::string const&  test_name_prefix = ""
        );


}

#endif
