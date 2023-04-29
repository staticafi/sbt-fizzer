#include <instrumentation/fuzz_target.hpp>
#include <instrumentation/data_record_id.hpp>

#include <iostream>

extern "C" {
    void __sbt_fizzer_method_under_test();
}

namespace instrumentation {
    std::unique_ptr<fuzz_target> sbt_fizzer_target = std::make_unique<fuzz_target>();
}

using namespace instrumentation;

#if PLATFORM() == PLATFORM_LINUX()
    #include <sys/prctl.h>
    #include <stdio.h>
#endif

int main(int argc, char* argv[]) {
    /* disable core dumps as this significantly slows down the termination 
    in case of a crash */
    #if PLATFORM() == PLATFORM_LINUX()
        if (prctl(PR_SET_DUMPABLE, 0) != 0) {
            std::cerr << "Failed to set dumpable flag\n";
        }
    #endif

    sbt_fizzer_target->shared_memory.open_or_create();
    sbt_fizzer_target->shared_memory.map_region();

    sbt_fizzer_target->load_config();
    sbt_fizzer_target->load_stdin();

    sbt_fizzer_target->shared_memory.clear();

    // Reserve the first two bytes for termination
    sbt_fizzer_target->shared_memory << data_record_id::invalid << data_record_id::invalid;

    __sbt_fizzer_method_under_test();

    sbt_fizzer_target->shared_memory.set_termination(target_termination::normal);

    return 0;
}