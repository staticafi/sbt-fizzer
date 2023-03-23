#include <fuzzing/fuzzers_map.hpp>
#include <fuzzing/fuzzer_dummy.hpp>
#include <fuzzhamm/fuzzer.hpp>
#include <klee_fuzzer/fuzzer.hpp>

namespace  fuzzing {


fuzzers_map const&  get_fuzzers_map()
{
    static fuzzers_map fm = []() -> fuzzers_map {
        fuzzers_map m;
        m.insert({ "dummy", create_fuzzer<fuzzer_dummy> });
        m.insert({ "fuzzhamm", create_fuzzer<fuzzhamm::fuzzer> });
        m.insert({ "klee", create_fuzzer<klee_fuzzer::fuzzer> });
        return m;
    }();
    return fm;
}


}
