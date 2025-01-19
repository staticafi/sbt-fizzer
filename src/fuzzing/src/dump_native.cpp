#include <fuzzing/dump_native.hpp>
#include <utility/math.hpp>
#include <utility/assumptions.hpp>
#include <iostream>
#include <iomanip>

namespace  fuzzing {


void  save_native_test(std::ostream&  ostr, execution_record const&  record)
{
    vecu64  chunk_values;
    for (natural_32_bit  k = 0U, i = 0U, n = (natural_32_bit)record.stdin_types.size(); i < n; ++i)
    {
        ASSUMPTION(num_bytes(record.stdin_types.at(i)) <= sizeof(chunk_values.back()));
        chunk_values.push_back(0U);
        for (natural_8_bit  j = 0U, m = num_bytes(record.stdin_types.at(i)); j < m; ++j)
            *(((natural_8_bit*)&chunk_values.back()) + j) = record.stdin_bytes.at(k + j);
        k += num_bytes(record.stdin_types.at(i));
    }

    std::string const  shift = "    ";

    ostr << "{\n";

    ostr << shift << "\"discovery\": " << ((record.flags & execution_record::BRANCH_DISCOVERED) != 0) << ",\n"
         << shift << "\"coverage\": " << ((record.flags & execution_record::BRANCH_COVERED) != 0) << ",\n"
         << shift << "\"crash\": " << ((record.flags & execution_record::EXECUTION_CRASHES) != 0) << ",\n"
         << shift << "\"boundary_violation\": " << ((record.flags & execution_record::BOUNDARY_CONDITION_VIOLATION) != 0) << ",\n"
         << shift << "\"medium_overflow\": " << ((record.flags & execution_record::MEDIUM_OVERFLOW) != 0) << ",\n"
         << shift << "\"empty_startup_trace\": " << ((record.flags & execution_record::EMPTY_STARTUP_TRACE) != 0) << ",\n"
         << shift << "\"analysis_name\": \"" << record.analysis_name << "\",\n"
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
        ostr << std::dec << '"' << to_string(record.stdin_types.at(i)) << "\",";
        ostr << '"';
        save_value(ostr, record.stdin_types.at(i), &chunk_values.at(i));
        ostr << '"';
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


}
