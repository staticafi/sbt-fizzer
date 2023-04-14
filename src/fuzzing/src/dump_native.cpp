#include <fuzzing/dump_native.hpp>
#include <fuzzing/termination_info.hpp>
#include <utility/math.hpp>
#include <utility/assumptions.hpp>
#include <iostream>
#include <fstream>
#include <iomanip>

namespace  fuzzing {


void  save_native_test(std::ostream&  ostr, execution_record const&  record)
{
    vecu64  chunk_values;
    for (natural_32_bit  k = 0U, i = 0U, n = (natural_32_bit)record.stdin_byte_counts.size(); i < n; ++i)
    {
        ASSUMPTION(record.stdin_byte_counts.at(i) <= 8U * sizeof(chunk_values.back()));
        chunk_values.push_back(0U);
        for (natural_8_bit  j = 0U, m = record.stdin_byte_counts.at(i); j < m; ++j)
            *(((natural_8_bit*)&chunk_values.back()) + j) = record.stdin_bytes.at(k + j);
        k += record.stdin_byte_counts.at(i);
    }

    std::string const  shift = "    ";

    ostr << "{\n";

    ostr << shift << "\"discovery\": " << ((record.flags & execution_record::BRANCH_DISCOVERED) != 0) << ",\n"
         << shift << "\"coverage\": " << ((record.flags & execution_record::BRANCH_COVERED) != 0) << ",\n"
         << shift << "\"crash\": " << ((record.flags & execution_record::EXECUTION_CRASHES) != 0) << ",\n"
         ;

    ostr << shift << "\"num_bytes\": " << record.stdin_bytes.size() << ",\n"
         << shift << "\"bytes\": [";
    for (natural_32_bit  i = 0U, n = (natural_32_bit)record.stdin_bytes.size(); i < n; ++i)
    {
        if (i % 16U == 0U) ostr << '\n' << shift << shift;
        ostr << '\"' << std::setfill('0') << std::setw(2) << std::hex << (natural_32_bit)record.stdin_bytes.at(i) << '\"';
        if (i + 1 < n)
            ostr << ", ";
    }
    ostr << '\n' << shift << "],\n";

    ostr << shift << "\"num_chunks\": " << chunk_values.size() << ",\n"
         << shift << "\"chunks\": [";
    for (natural_32_bit  i = 0U, n = (natural_32_bit)chunk_values.size(); i < n; ++i)
    {
        if (i % 8U == 0U) ostr << '\n' << shift << shift;
        ostr << std::dec << (natural_32_bit)record.stdin_byte_counts.at(i) / 8U << ','
             << std::dec << (natural_32_bit)chunk_values.at(i);
        if (i + 1 < n)
            ostr << ',' << shift;
    }
    ostr << '\n' << shift << "],\n";

    ostr << shift << "\"num_branchings\": " << record.path.size() << ",\n"
         << shift << "\"branchings\": [";
    for (natural_32_bit  i = 0U, n = (natural_32_bit)record.path.size(); i < n; ++i)
    {
        if (i % 4U == 0U) ostr << '\n' << shift << shift;
        ostr << std::dec << record.path.at(i).first.id << ','
             << std::dec << record.path.at(i).first.context_hash << ','
             << (record.path.at(i).second ? 1 : 0);
        if (i + 1 < n)
            ostr << ',' << shift;
    }
    ostr << '\n' << shift << "]\n";

    ostr << "}\n";
}

void  save_native_output(
        std::filesystem::path const&  output_dir,
        std::vector<execution_record> const&  records,
        std::string const&  test_name_prefix
        )
{
    for (natural_32_bit  i = 0U, n = (natural_32_bit)records.size(); i < n; ++i)
    {
        std::filesystem::path const  test_file_path = output_dir / (test_name_prefix + "_" + std::to_string(i + 1U) + ".json");
        std::ofstream  ostr(test_file_path.c_str(), std::ios::binary);
        save_native_test(ostr, records.at(i));
    }
}


}
