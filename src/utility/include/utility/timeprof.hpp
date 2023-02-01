#ifndef UTILITY_TIMEPROF_HPP_INCLUDED
#   define UTILITY_TIMEPROF_HPP_INCLUDED

#   include <utility/basic_numeric_types.hpp>
#   include <utility/config.hpp>
#   include <chrono>
#   include <iosfwd>
#   include <string>
#   include <vector>

#   if !((BUILD_DEBUG() == 1 && defined(DEBUG_DISABLE_TIME_PROFILING)) ||           \
         (BUILD_RELEASE() == 1 && defined(RELEASE_DISABLE_TIME_PROFILING)))
#       define TMPROF_BLOCK()                                                       \
            static ::tmprof_internal_private_implementation_details::Record* const  \
                ___tmprof__Record__pointer__ =                                      \
                ::tmprof_internal_private_implementation_details::                  \
                    create_new_record_for_block(__FILE__,__LINE__,__FUNCTION__);    \
            ::tmprof_internal_private_implementation_details::block_stop_watches    \
                const  ___tmprof__stop_watches__ ( ___tmprof__Record__pointer__ );
#       define TMPROF_PRINT_TO_STREAM(stream) print_time_profile_to_stream(stream);
#       define TMPROF_PRINT_TO_FILE(fname,extend_fname_by_timestamp)                         \
            print_time_profile_to_file(fname,extend_fname_by_timestamp);
#   else
#       define TMPROF_BLOCK()
#       define TMPROF_PRINT_TO_STREAM(stream)
#       define TMPROF_PRINT_TO_FILE(stream)
#   endif


namespace tmprof_internal_private_implementation_details {


struct Record;

Record*  create_new_record_for_block(char const* const file, int const line,
                                     char const* const func);


struct block_stop_watches
{
    explicit block_stop_watches(Record* const  storage_for_results);
    ~block_stop_watches();
private:
    Record*  m_storage_for_results;
    std::chrono::system_clock::time_point  m_start_time;
};


}


struct time_profile_data_of_block
{
    explicit time_profile_data_of_block(
            natural_64_bit  num_executions,
            float_64_bit  genuine_duration,
            float_64_bit  summary_duration,
            float_64_bit  longest_duration,
            natural_32_bit  num_running_executions,
            std::string  file_name,
            natural_32_bit  line,
            std::string  function_name
            );

    natural_64_bit  number_of_executions() const;
    float_64_bit  genuine_duration_of_all_executions_in_seconds() const;
    float_64_bit  summary_duration_of_all_executions_in_seconds() const;
    float_64_bit  duration_of_longest_execution_in_seconds() const;
    natural_32_bit  num_running_executions() const;

    std::string const&  file_name() const;
    natural_32_bit  line() const;
    std::string const&  function_name() const;

private:
    natural_64_bit  m_num_executions;
    float_64_bit  m_genuine_duration;
    float_64_bit  m_summary_duration;
    float_64_bit  m_longest_duration;
    natural_32_bit  m_num_running_executions;
    std::string  m_file_name;
    natural_32_bit  m_line;
    std::string  m_function_name;
};


void copy_time_profile_data_of_all_measured_blocks_into_vector(
        std::vector<time_profile_data_of_block>& storage_for_the_copy_of_data,
        bool const  sort_data = true
        );

float_64_bit  compute_genuine_duration_of_all_executions_of_all_blocks_in_seconds(
        std::vector<time_profile_data_of_block> const& collected_profile_data
        );

float_64_bit  compute_summary_duration_of_all_executions_of_all_blocks_in_seconds(
        std::vector<time_profile_data_of_block> const& collected_profile_data
        );

std::chrono::system_clock::time_point  get_time_profiling_start_time_point();

std::ostream& print_time_profile_data_to_stream(
        std::ostream& os,
        std::vector<time_profile_data_of_block> const& data
        );

std::ostream& print_time_profile_to_stream(std::ostream& os);

void print_time_profile_to_file(std::string const& file_path_name,
                                bool const extend_file_name_by_timestamp);


#endif
