#ifndef UTILITY_TIMESTAMP_HPP_INCLUDED
#   define UTILITY_TIMESTAMP_HPP_INCLUDED

#   include <string>


std::string const&  get_program_start_timestamp();
std::string  compute_timestamp();
std::string  extend_file_path_name_by_timestamp(
		std::string const& file_path_name,
		std::string const& suffix,
		bool const use_start_timestamp = true
		);


#endif
