#include <fuzzing/dump.hpp>
#include <connection/client.hpp>
#include <iomodels/iomanager.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/math.hpp>
#include <utility/log.hpp>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

namespace  fuzzing {


void  print_fuzzing_configuration(
        std::ostream&  ostr,
        std::string const&  benchmark,
        iomodels::configuration const&  ioconfig,
        termination_info const&  terminator
        )
{
    std::string const  shift = "    ";
    ostr << "{\n"
         << shift << "\"benchmark\": \"" << benchmark << "\",\n"
         << shift << "\"max_executions\": " << terminator.max_executions << ",\n"
         << shift << "\"max_seconds\": " << terminator.max_seconds << ",\n"
         << shift << "\"max_trace_length\": " << ioconfig.max_trace_length << ",\n"
         << shift << "\"max_br_instr_trace_length\": " << ioconfig.max_br_instr_trace_length << ",\n"
         << shift << "\"max_stack_size\": " << (int)ioconfig.max_stack_size << ",\n"
         << shift << "\"max_stdin_bytes\": " << ioconfig.max_stdin_bytes << ",\n"
         << shift << "\"max_exec_milliseconds\": " << ioconfig.max_exec_milliseconds << ",\n"
         << shift << "\"max_exec_megabytes\": " << ioconfig.max_exec_megabytes << ",\n"
         << shift << "\"stdin_model\": \"" << ioconfig.stdin_model_name << "\",\n"
         << shift << "\"stdout_model\": \"" << ioconfig.stdout_model_name << "\"\n"
         << "}"
         ;
}


void  log_fuzzing_configuration(
        std::string const&  benchmark,
        iomodels::configuration const&  ioconfig,
        termination_info const&  terminator
        )
{
    std::stringstream sstr;
    print_fuzzing_configuration(sstr, benchmark, ioconfig, terminator);
    LOG(LSL_INFO, sstr.str());
}


void  save_fuzzing_configuration(
        std::filesystem::path const&  output_dir,
        std::string const&  benchmark,
        iomodels::configuration const&  ioconfig,
        termination_info const&  terminator
        )
{
    std::filesystem::path const  test_file_path = output_dir / (benchmark + "_config.json");
    std::ofstream  ostr(test_file_path.c_str(), std::ios::binary);
    print_fuzzing_configuration(ostr, benchmark, ioconfig, terminator);
}


void  print_analysis_outcomes(std::ostream&  ostr, analysis_outcomes const&  results)
{
    std::string const  shift = "    ";

    ostr << "{\n";

    ostr << shift << "\"termination_type\": \"";
    switch (results.termination_type)
    {
    case analysis_outcomes::TERMINATION_TYPE::NORMAL:
        ostr << "NORMAL";
        break;
    case analysis_outcomes::TERMINATION_TYPE::SERVER_INTERNAL_ERROR:
        ostr << "SERVER_INTERNAL_ERROR";
        break;
    case analysis_outcomes::TERMINATION_TYPE::CLIENT_COMMUNICATION_ERROR:
        ostr << "CLIENT_COMMUNICATION_ERROR";
        break;
    case analysis_outcomes::TERMINATION_TYPE::UNCLASSIFIED_ERROR:
        ostr << "UNCLASSIFIED_ERROR";
        break;
    default: { UNREACHABLE(); break; }
    }
    ostr << "\",\n";

    if (results.termination_type == analysis_outcomes::TERMINATION_TYPE::NORMAL)
    {
        ostr << shift << "\"termination_reason\": \"";
        switch (results.termination_reason)
        {
        case fuzzer::TERMINATION_REASON::ALL_REACHABLE_BRANCHINGS_COVERED:
            ostr << "ALL_REACHABLE_BRANCHINGS_COVERED";
            break;
        case fuzzer::TERMINATION_REASON::FUZZING_STRATEGY_DEPLETED:
            ostr << "FUZZING_STRATEGY_DEPLETED";
            break;
        case fuzzer::TERMINATION_REASON::TIME_BUDGET_DEPLETED:
            ostr << "TIME_BUDGET_DEPLETED";
            break;
        case fuzzer::TERMINATION_REASON::EXECUTIONS_BUDGET_DEPLETED:
            ostr << "EXECUTIONS_BUDGET_DEPLETED";
            break;
        default: { UNREACHABLE(); break; }
        }
        ostr << "\",\n";
    }
    else
        ostr << shift << "\"error_message\": \"" << results.error_message << "\",\n";

    std::vector<std::string>  warnings;
    if (results.fuzzer_statistics.leaf_nodes_created != results.fuzzer_statistics.leaf_nodes_destroyed)
        warnings.push_back("The number of created and destroyed leaf nodes differ.");
    if (results.fuzzer_statistics.nodes_created != results.fuzzer_statistics.nodes_destroyed)
        warnings.push_back("The number of created and destroyed nodes differ => Memory leak!");
    if (results.input_flow_statistics.start_calls != results.input_flow_statistics.stop_calls)
        warnings.push_back("The number of starts does not match to the number of stops in the input_flow analysis.");
    if (!warnings.empty())
    {
        ostr << shift << "\"WARNINGS\": [\n";
        for (std::size_t  i = 0, n = warnings.size(); i < n; ++i)
        {
            ostr << shift << shift << "\"" << warnings.at(i) << "\"";
            if (i + 1 < n)
                ostr << ',';
            ostr << '\n';
        }
        ostr << shift << "],\n";
    }

    ostr << shift << "\"num_executions\": " << results.num_executions << ",\n"
         << shift << "\"num_elapsed_seconds\": " << results.num_elapsed_seconds << ",\n"
         << shift << "\"input_flow_analysis\": {\n"
         << shift << shift << "\"start_calls\": " << results.input_flow_statistics.start_calls << ",\n"
         << shift << shift << "\"stop_calls\": " << results.input_flow_statistics.stop_calls << ",\n"
         << shift << shift << "\"num_failures\": " << results.input_flow_statistics.num_failures << ",\n"
         << shift << shift << "\"errors\": [";
    {
        bool first1{ true };
        for (std::string const&  error : results.input_flow_statistics.errors)
        {
            if (first1) first1 = false; else ostr << ",";
            ostr << "\n" << shift << shift << shift << error;
        }
        ostr << "\n";
    }
    ostr << shift << shift << "],\n"
         << shift << shift << "\"warnings\": [";
    {
        bool first1{ true };
        for (std::string const& warning : results.input_flow_statistics.warnings) 
        {
            if (first1) first1 = false; else ostr << ",";
            ostr << "\n" << shift << shift << shift << warning;
        }
        ostr << "\n";
    }
    ostr << shift << shift << "],\n"
         << shift << shift << "\"complexity\": [";
    {
        bool first1{ true };
        for (auto const& key_and_value : results.input_flow_statistics.complexity)
        {
            if (first1) first1 = false; else ostr << ",";
            ostr << "\n";
            ostr << shift << shift << shift << "{ "
                 << "\"trace_index\": " << key_and_value.first.first
                 << ", \"stdin_bytes\": " << key_and_value.first.second
                 << ", \"durations\": [ ";
            bool first2{ true };
            for (auto const time : key_and_value.second)
            {
                if (first2) first2 = false; else ostr << ", ";
                ostr << time;
            }
            ostr << " ] }";
        }
        ostr << "\n";
    }
    ostr << shift << shift << "]\n"
         << shift << "},\n"
         << shift << "\"bitshare_analysis\": {\n"
         << shift << shift << "\"generated_inputs\": " << results.bitshare_statistics.generated_inputs << ",\n"
         << shift << shift << "\"hits\": " << results.bitshare_statistics.hits << ",\n"
         << shift << shift << "\"misses\": " << results.bitshare_statistics.misses << ",\n"
         << shift << shift << "\"start_calls\": " << results.bitshare_statistics.start_calls << ",\n"
         << shift << shift << "\"stop_calls_regular\": " << results.bitshare_statistics.stop_calls_regular << ",\n"
         << shift << shift << "\"stop_calls_early\": " << results.bitshare_statistics.stop_calls_early << ",\n"
         << shift << shift << "\"stop_calls_instant\": " << results.bitshare_statistics.stop_calls_instant << ",\n"
         << shift << shift << "\"num_locations\": " << results.bitshare_statistics.num_locations << ",\n"
         << shift << shift << "\"num_insertions\": " << results.bitshare_statistics.num_insertions << ",\n"
         << shift << shift << "\"num_deletions\": " << results.bitshare_statistics.num_deletions << "\n"
         << shift << "},\n"
         << shift << "\"fuzzer\": {\n"
         << shift << shift << "\"leaf_nodes_created\": " << results.fuzzer_statistics.leaf_nodes_created << ",\n"
         << shift << shift << "\"leaf_nodes_destroyed\": " << results.fuzzer_statistics.leaf_nodes_destroyed << ",\n"
         << shift << shift << "\"nodes_created\": " << results.fuzzer_statistics.nodes_created << ",\n"
         << shift << shift << "\"nodes_destroyed\": " << results.fuzzer_statistics.nodes_destroyed << ",\n"
         << shift << shift << "\"max_leaf_nodes\": " << results.fuzzer_statistics.max_leaf_nodes << ",\n"
         << shift << shift << "\"max_input_width\": " << results.fuzzer_statistics.max_input_width << ",\n"
         << shift << shift << "\"longest_branch\": " << results.fuzzer_statistics.longest_branch << ",\n"
         << shift << shift << "\"traces_to_crash\": " << results.fuzzer_statistics.traces_to_crash << ",\n"
         << shift << shift << "\"traces_to_boundary_violation\": " << results.fuzzer_statistics.traces_to_boundary_violation << ",\n"
         << shift << shift << "\"traces_to_medium_overflow\": " << results.fuzzer_statistics.traces_to_medium_overflow << ",\n"
         << shift << shift << "\"strategy_primary_loop_head\": " << results.fuzzer_statistics.strategy_primary_loop_head << ",\n"
         << shift << shift << "\"strategy_primary_sensitive\": " << results.fuzzer_statistics.strategy_primary_sensitive << ",\n"
         << shift << shift << "\"strategy_primary_untouched\": " << results.fuzzer_statistics.strategy_primary_untouched << ",\n"
         << shift << shift << "\"strategy_primary_iid_twins\": " << results.fuzzer_statistics.strategy_primary_iid_twins << ",\n"
         << shift << shift << "\"strategy_monte_carlo\": " << results.fuzzer_statistics.strategy_monte_carlo << ",\n"
         << shift << shift << "\"coverage_failure_resets\": " << results.fuzzer_statistics.coverage_failure_resets << "\n"
         << shift << "},\n"
         ;

    ostr << shift << "\"num_covered_branchings\": " << results.covered_branchings.size() << ",\n"
         << shift << "\"covered_branchings\": [";
    for (std::size_t  i = 0, n = results.covered_branchings.size(); i < n; ++i)
    {
        if (i % 4U == 0U) ostr << '\n' << shift << shift;
        ostr << std::dec << results.covered_branchings.at(i).id << ','
             << std::dec << results.covered_branchings.at(i).context_hash;
        if (i + 1 < n)
            ostr << ',' << shift;
    }
    ostr << '\n' << shift << "],\n";

    ostr << shift << "\"num_uncovered_branchings\": " << results.uncovered_branchings.size() << ",\n"
         << shift << "\"uncovered_branchings\": [";
    for (std::size_t  i = 0, n = results.uncovered_branchings.size(); i < n; ++i)
    {
        if (i % 4U == 0U) ostr << '\n' << shift << shift;
        ostr << std::dec << results.uncovered_branchings.at(i).first.id << ','
             << std::dec << results.uncovered_branchings.at(i).first.context_hash << ','
             << (results.uncovered_branchings.at(i).second ? 1 : 0);
        if (i + 1 < n)
            ostr << ',' << shift;
    }
    ostr << '\n' << shift << "],\n";

    ostr << shift << "\"output_statistics\": {\n";
    for (auto  it = results.output_statistics.begin(); it != results.output_statistics.end(); ++it)
    {
        ostr << shift << shift << '\"' << it->first << "\": {\n";
        ostr << shift << shift << shift << "\"num_generated_tests\": " << it->second.num_generated_tests << ",\n";
        ostr << shift << shift << shift << "\"num_crashes\": " << it->second.num_crashes << ",\n";
        ostr << shift << shift << shift << "\"num_boundary_violations\": " << it->second.num_boundary_violations << "\n";
        ostr << shift << shift << '}' << (std::next(it) != results.output_statistics.end() ? "," : "") << '\n';
    }
    ostr << shift << "}\n";

    ostr << "}";
}


void  log_analysis_outcomes(analysis_outcomes const&  results)
{
    std::stringstream sstr;
    print_analysis_outcomes(sstr, results);
    LOG(LSL_INFO, sstr.str());
}


void  save_analysis_outcomes(
        std::filesystem::path const&  output_dir,
        std::string const&  benchmark,
        analysis_outcomes const&  results
        )
{
    std::filesystem::path const  test_file_path = output_dir / (benchmark + "_outcomes.json");
    std::ofstream  ostr(test_file_path.c_str(), std::ios::binary);
    print_analysis_outcomes(ostr, results);
}


void  print_optimization_configuration(std::ostream&  ostr, optimizer::configuration const&  config)
{
    std::string const  shift = "    ";
    ostr << "{\n"
         << shift << "\"max_seconds\": " << config.max_seconds << ",\n"
         << shift << "\"max_trace_length\": " << config.max_trace_length << ",\n"
         << shift << "\"max_stdin_bytes\": " << config.max_stdin_bytes << "\n"
         << "}"
         ;
}


void  log_optimization_configuration(optimizer::configuration const&  config)
{
    std::stringstream sstr;
    print_optimization_configuration(sstr, config);
    LOG(LSL_INFO, sstr.str());
}


void  save_optimization_configuration(
        std::filesystem::path const&  output_dir,
        std::string const&  benchmark,
        optimizer::configuration const&  config
        )
{
    std::filesystem::path const  test_file_path = output_dir / (benchmark + "_config_opt.json");
    std::ofstream  ostr(test_file_path.c_str(), std::ios::binary);
    print_optimization_configuration(ostr, config);
}


void  print_optimization_outcomes(std::ostream&  ostr, optimization_outcomes const&  results)
{
    std::string const  shift = "    ";

    ostr << "{\n";

    ostr << shift << "\"termination_type\": \"";
    switch (results.termination_type)
    {
    case optimization_outcomes::TERMINATION_TYPE::NORMAL:
        ostr << "NORMAL";
        break;
    case optimization_outcomes::TERMINATION_TYPE::SERVER_INTERNAL_ERROR:
        ostr << "SERVER_INTERNAL_ERROR";
        break;
    case optimization_outcomes::TERMINATION_TYPE::CLIENT_COMMUNICATION_ERROR:
        ostr << "CLIENT_COMMUNICATION_ERROR";
        break;
    case optimization_outcomes::TERMINATION_TYPE::UNCLASSIFIED_ERROR:
        ostr << "UNCLASSIFIED_ERROR";
        break;
    default: { UNREACHABLE(); break; }
    }
    ostr << "\",\n";

    if (results.termination_type == optimization_outcomes::TERMINATION_TYPE::NORMAL)
    {
        ostr << shift << "\"termination_reason\": \"";
        switch (results.termination_reason)
        {
        case optimizer::TERMINATION_REASON::ALL_TESTS_WERE_PROCESSED:
            ostr << "ALL_TESTS_WERE_PROCESSED";
            break;
        case optimizer::TERMINATION_REASON::TIME_BUDGET_DEPLETED:
            ostr << "TIME_BUDGET_DEPLETED";
            break;
        default: { UNREACHABLE(); break; }
        }
        ostr << "\",\n";
    }
    else
        ostr << shift << "\"error_message\": \"" << results.error_message << "\",\n";

    ostr << shift << "\"num_executions\": " << results.statistics.num_executions << ",\n"
         << shift << "\"num_seconds\": " << results.statistics.num_seconds << ",\n"
         << shift << "\"num_extended_tests\": " << results.statistics.num_extended_tests << ",\n"
         ;

    ostr << shift << "\"num_covered_branchings\": " << results.covered_branchings.size() << ",\n"
         << shift << "\"covered_branchings\": [";
    for (std::size_t  i = 0, n = results.covered_branchings.size(); i < n; ++i)
    {
        if (i % 4U == 0U) ostr << '\n' << shift << shift;
        ostr << std::dec << results.covered_branchings.at(i).id << ','
             << std::dec << results.covered_branchings.at(i).context_hash;
        if (i + 1 < n)
            ostr << ',' << shift;
    }
    ostr << '\n' << shift << "],\n";

    ostr << shift << "\"num_uncovered_branchings\": " << results.uncovered_branchings.size() << ",\n"
         << shift << "\"uncovered_branchings\": [";
    for (std::size_t  i = 0, n = results.uncovered_branchings.size(); i < n; ++i)
    {
        if (i % 4U == 0U) ostr << '\n' << shift << shift;
        ostr << std::dec << results.uncovered_branchings.at(i).first.id << ','
             << std::dec << results.uncovered_branchings.at(i).first.context_hash << ','
             << (results.uncovered_branchings.at(i).second ? 1 : 0);
        if (i + 1 < n)
            ostr << ',' << shift;
    }
    ostr << '\n' << shift << "]\n";

    ostr << "}";
}


void  log_optimization_outcomes(optimization_outcomes const&  results)
{
    std::stringstream sstr;
    print_optimization_outcomes(sstr, results);
    LOG(LSL_INFO, sstr.str());
}


void  save_optimization_outcomes(
        std::filesystem::path const&  output_dir,
        std::string const&  benchmark,
        optimization_outcomes const&  results
        )
{
    std::filesystem::path const  test_file_path = output_dir / (benchmark + "_outcomes_opt.json");
    std::ofstream  ostr(test_file_path.c_str(), std::ios::binary);
    print_optimization_outcomes(ostr, results);
}


}
