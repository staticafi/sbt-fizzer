#ifndef FUZZING_DUMP_HPP_INCLUDED
#   define FUZZING_DUMP_HPP_INCLUDED

#   include <fuzzing/analysis_outcomes.hpp>
#   include <fuzzing/optimization_outcomes.hpp>
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
void  log_fuzzing_configuration(
        std::string const&  benchmark,
        iomodels::iomanager::configuration const&  ioconfig,
        termination_info const&  terminator
        );
void  save_fuzzing_configuration(
        std::filesystem::path const&  output_dir,
        std::string const&  benchmark,
        iomodels::iomanager::configuration const&  ioconfig,
        termination_info const&  terminator
        );

void  print_analysis_outcomes(std::ostream&  ostr, analysis_outcomes const&  results);
void  log_analysis_outcomes(analysis_outcomes const&  results);
void  save_analysis_outcomes(
        std::filesystem::path const&  output_dir,
        std::string const&  benchmark,
        analysis_outcomes const&  results
        );

void  save_debug_data_to_directory(
        std::filesystem::path const&  output_dir,
        std::string const&  name_prefix,
        std::unordered_map<std::string, std::string> const&  data
        );

void  print_optimization_configuration(
        std::ostream&  ostr,
        std::vector<execution_record> const&  input_test_suite,
        termination_info const&  terminator
        );
void  log_optimization_configuration(
        std::vector<execution_record> const&  input_test_suite,
        termination_info const&  terminator
        );
void  save_optimization_configuration(
        std::filesystem::path const&  output_dir,
        std::string const&  benchmark,
        std::vector<execution_record> const&  input_test_suite,
        termination_info const&  terminator
        );
void  print_optimization_outcomes(std::ostream&  ostr, optimization_outcomes const&  results);
void  log_optimization_outcomes(optimization_outcomes const&  results);
void  save_optimization_outcomes(
        std::filesystem::path const&  output_dir,
        std::string const&  benchmark,
        optimization_outcomes const&  results
        );


}

#endif
