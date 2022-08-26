#include <fizz/program_info.hpp>
#include <fizz/program_options.hpp>
#include <benchmarks/benchmarks.hpp>
#include <connection/server_main.hpp>
#include <connection/client_main.hpp>
#include <fuzzing/termination_info.hpp>
#include <fuzzing/analysis_outcomes.hpp>
#include <fuzzing/dump.hpp>
#include <utility/timeprof.hpp>
#include <utility/log.hpp>
#include <iostream>


struct test_props
{
    std::string  fuzzer_name;
    std::string  benchmark_name;
    fuzzing::termination_info  terminator;
    fuzzing::analysis_outcomes  results;
};


void test()
{
    TMPROF_BLOCK();

    std::vector<test_props>  tests = {
        { "fuzzhamm", "c_string_count_chars", { 2050U, 300U }, {} },
        { "fuzzhamm", "int8_if_x_equal_c", { 100U, 300U }, {} },
        { "fuzzhamm", "int16_equal", { 400U, 300U }, {} },
        //{ "fuzzhamm", "c_string_parse_two_ints", { 10000U, 300U }, {} },
        { "fuzzhamm", "float_if_x_eq_c", { 6100U, 300U }, {} },
        { "fuzzhamm", "int16_less", { 200U, 300U }, {} },
        { "fuzzhamm", "nested_ifs", { 400U, 300U }, {} },
        { "fuzzhamm", "int8_if_x_equal_y_c", { 100U, 300U }, {} },
        { "fuzzhamm", "int8_if_x_lt_c", { 100U, 300U }, {} },
        { "fuzzhamm", "int8_if_x_ge_c", { 100U, 300U }, {} },
        { "fuzzhamm", "int8_if_x_xor_a_eq_b", { 100U, 300U }, {} },
        { "fuzzhamm", "int8_if_hash_x_y_z_eq_c", { 153900U, 300U }, {} },
        { "fuzzhamm", "int16_if_x_equal_c", { 300U, 300U }, {} },
        { "fuzzhamm", "int16_if_x_equal_y_c", { 200U, 300U }, {} },
        { "fuzzhamm", "int16_if_x_ge_c", { 100U, 300U }, {} },
        { "fuzzhamm", "int16_if_x_lt_c", { 100U, 300U }, {} },
        { "fuzzhamm", "int16_if_x_xor_a_eq_b", { 200U, 300U }, {} },
        { "fuzzhamm", "int16_if_parabola", { 100U, 300U }, {} },
        { "fuzzhamm", "uint16_if_parabola", { 100U, 300U }, {} },
        { "fuzzhamm", "int32_if_x_equal_c", { 700U, 300U }, {} },
        { "fuzzhamm", "int32_if_x_equal_y_c", { 800U, 300U }, {} },
        { "fuzzhamm", "int32_if_x_ge_c", { 100U, 300U }, {} },
        { "fuzzhamm", "int32_if_x_lt_c", { 100U, 300U }, {} },
        { "fuzzhamm", "int32_if_x_xor_a_eq_b", { 1200U, 300U }, {} },
        { "fuzzhamm", "int32_if_parabola", { 200U, 300U }, {} },
        { "fuzzhamm", "int32_logical_or_two_vars", { 200U, 300U }, {} },
        { "fuzzhamm", "int32_ackermann", { 250U, 300U }, {} },
        { "fuzzhamm", "uint32_if_parabola", { 200U, 300U }, {} },
        { "fuzzhamm", "bool_flag_one_and_two", { 410U, 300U }, {} },
    };

    natural_32_bit  num_failed_tests = 0U;
    for (test_props&  test : tests)
    {
        std::cout << "TEST: Fuzzing '" << test.benchmark_name << "' by '" << test.fuzzer_name << "' ... ";

        connection::client_main(test.benchmark_name);
        test.results = connection::server_main(test.fuzzer_name, test.terminator);

        if (test.results.uncovered_branchings.empty())
            std::cout << "OK" << std::endl;
        else
        {
            ++num_failed_tests;
            std::cout << "FAILURE" << std::endl;
            LOG(LSL_ERROR, "TEST: Fuzzing '" << test.benchmark_name << "' by '" << test.fuzzer_name << "' ... FAILURE");
        }
    }

    if (num_failed_tests > 0U)
    {
        std::cout << "\n\nDetails of failed tests:\n\n\n";
        for (test_props const&  test : tests)
            if (!test.results.uncovered_branchings.empty())
            {
                fuzzing::print_fuzzing_configuration(std::cout, test.fuzzer_name, test.benchmark_name, test.terminator);
                fuzzing::print_analysis_outcomes(std::cout, test.results, false);
                std::cout << std::endl << std::endl;
            }
    }

    std::cout << "<NUM_TESTS: " << tests.size() << ">\n";
    std::cout << "<NUM_FAILED_TESTS: " << num_failed_tests  << ">";

    std::cout.flush();
}
