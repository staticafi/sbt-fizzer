#include <fuzzhamm/execution_trace_utils.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/development.hpp>
#include <iostream>

namespace  fuzzhamm {


void  to_json(std::ostream&  ostr, execution_trace const&  trace, bool const  dump_trace, bool const  dump_dbg_info)
{
    ostr << "{ \"magic\": \"SBT-EFT\", \"version\": \"0.1\",\n";

    if (!trace.input_stdin.empty())
    {
        vecu8  byte_values;
        bits_to_bytes(trace.input_stdin, byte_values);

        ostr << "\"input_tc\": {\n";

        ostr << "  \"bytes\": [";
        if (byte_values.size() > 16ULL)
            ostr << "\n    ";
        else
            ostr << ' ';
        for (natural_32_bit  i = 0U, n = (natural_32_bit)byte_values.size(); i < n; ++i)
        {
            if (i != 0U)
                ostr << ',';
            if (i > 0U && i % 16U == 0U)
                ostr << "\n    ";
            ostr << (natural_32_bit)byte_values.at(i);
        }
        ostr << " ]";

        ostr << ",\n  \"chunks\": [";
        if (trace.input_stdin_counts.size() > 16ULL)
            ostr << "\n    ";
        else
            ostr << ' ';
        for (natural_32_bit  i = 0U, n = (natural_32_bit)trace.input_stdin_counts.size(); i < n; ++i)
        {
            if (i != 0U)
                ostr << ',';
            if (i > 0U && i % 16U == 0U)
                ostr << "\n    ";
            ostr << (natural_32_bit)trace.input_stdin_counts.at(i) / 8U;
        }
        ostr << " ]";

        if (dump_dbg_info)
        {
            ostr << ",\n  \"dbg_values\": [";
            if (trace.input_stdin_counts.size() > 16ULL)
                ostr << "\n    ";
            else
                ostr << ' ';
            for (natural_32_bit  k = 0U, i = 0U, n = (natural_32_bit)trace.input_stdin_counts.size(); i < n; ++i)
            {
                if (i != 0U)
                    ostr << ',';
                if (i > 0U && i % 16U == 0U)
                    ostr << "\n    ";

                natural_32_bit  value = 0U;
                {
                    INVARIANT(trace.input_stdin_counts.at(i) < 8U * sizeof(value));
                    for (natural_8_bit  j = 0U, m = trace.input_stdin_counts.at(i) / 8U; j < m; ++j)
                        *(((natural_8_bit*)&value) + j) = byte_values.at(k + j);
                    k += trace.input_stdin_counts.at(i) / 8U;
                }

                ostr << value;
            }
            ostr << " ]";
        }

        ostr << " }";
    }

    if (dump_trace)
    {
        ostr << ",\n\"trace\": [\n";
        for (natural_32_bit  i = 0U, n = (natural_32_bit)trace.branching_records.size(); i < n; ++i)
        {
            if (i != 0U)
                ostr << ",\n";
            auto const&  rec = trace.branching_records.at(i);
            ostr << "  { \"loc\": " << rec.coverage_info.branching_id
                 << ", \"dir\": " << std::noboolalpha << rec.coverage_info.covered_branch
                 << ", \"idx_tc\": [ ";

            std::vector<natural_16_bit> indices(rec.sensitive_stdin_bits.begin(), rec.sensitive_stdin_bits.end());
            if (indices.empty())
                indices.insert(indices.end(), rec.diverged_stdin_bits.begin(), rec.diverged_stdin_bits.end());
            std::sort(indices.begin(), indices.end());
            for (natural_32_bit  j = 0U, m = (natural_32_bit)indices.size(); j < m; ++j)
            {
                if (j != 0U)
                    ostr << ',';
                ostr << indices.at(j);
            }
            ostr << " ] }";
        }
        ostr << " ]\n";
    }

    ostr << '}';
}


}
