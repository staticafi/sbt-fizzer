#include <fuzzing/dump_testcomp.hpp>

#include <utility/assumptions.hpp>
#include <utility/math.hpp>
#include <utility/log.hpp>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <chrono>
#if COMPILER() == COMPILER_VC()
#   pragma warning(disable:4996) // warning C4996: 'localtime': This function or variable may be unsafe.
#endif


namespace fuzzing {


void save_testcomp_metadata(std::ostream&  ostr, const std::string& version, const std::string& program_file) {
    ostr << "<?xml version='1.0' encoding='UTF-8' standalone='no'?>\n";
    ostr << "<!DOCTYPE test-metadata PUBLIC \"+//IDN sosy-lab.org//DTD ";
    ostr << "test-format test-metadata 1.1//EN\" ";
    ostr << "\"https://sosy-lab.org/test-format/test-metadata-1.1.dtd\">\n";
    ostr << "<test-metadata>\n";
    ostr << "  <sourcecodelang>C</sourcecodelang>\n";
    ostr << "  <producer>SBT-Fizzer " << version << "</producer>\n";
    ostr << "  <specification>COVER( init(main()), FQL(COVER EDGES(@DECISIONEDGE)) )</specification>\n";
    ostr << "  <programfile>" << program_file << "</programfile>\n";
    ostr << "  <programhash>null</programhash>\n";
    ostr << "  <entryfunction>main</entryfunction>\n";
    ostr << "  <architecture>32bit</architecture>\n";
    auto now = std::time(0);
    auto local = std::localtime(&now);
    ostr << "  <creationtime>" << std::put_time(local, "%Y-%m-%d %H:%M:%S") << "</creationtime>\n";
    ostr << "</test-metadata>";
}


void save_testcomp_test(std::ostream& ostr, const trace_with_coverage_info& trace) {
    ostr << "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n";
    ostr << "<!DOCTYPE testcase PUBLIC \"+//IDN sosy-lab.org//DTD test-format testcase ";
    ostr << "1.1//EN\" \"https://sosy-lab.org/test-format/testcase-1.1.dtd\">\n";
    ostr << "<testcase>\n";
    save_testcomp_test_inputs(ostr, trace);
    ostr << "</testcase>";
}


void save_testcomp_test_inputs(std::ostream& ostr, const trace_with_coverage_info& trace) {
    vecu8  byte_values;
    bits_to_bytes(trace.input_stdin, byte_values);

    natural_32_bit offset = 0;
    for (natural_8_bit input_chunk: trace.input_stdin_counts) {
        ostr << "  <input>0x";
        for (natural_8_bit i = input_chunk / 8; i-- > 0;) {
            ostr << std::setfill('0') << std::setw(2) << std::hex << (natural_32_bit)byte_values.at(offset + i);
        }
        ostr << "</input>\n";
        offset += input_chunk / 8;
    }
}


void save_testcomp_output(
    std::filesystem::path const& output_dir,
    std::vector<trace_with_coverage_info> const&  traces_forming_coverage,
    const std::string& test_name_prefix,
    const std::string& version,
    const std::string& program_file
    ) {
        {
            std::filesystem::path metadata = output_dir / "metadata.xml";
            std::ofstream ostr(metadata.c_str(), std::ios::binary);
            save_testcomp_metadata(ostr, version, program_file);
        }
        
        for (std::size_t i = 0U; i < traces_forming_coverage.size(); ++i) {
            std::filesystem::path test_file_path = output_dir / (test_name_prefix + "_" + std::to_string(i + 1U) + ".xml");
            std::ofstream  ostr(test_file_path.c_str(), std::ios::binary);
            save_testcomp_test(ostr, traces_forming_coverage[i]);
        }
    }

}