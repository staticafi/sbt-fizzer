set(THIS_TARGET_NAME fuzzing)

add_library(${THIS_TARGET_NAME}
    ./include/fuzzing/fuzzer_base.hpp
    ./src/fuzzer_base.cpp

    ./include/fuzzing/termination_info.hpp
    ./include/fuzzing/analysis_outcomes.hpp

    ./include/fuzzing/fuzzer_dummy.hpp
    ./src/fuzzer_dummy.cpp

    ./include/fuzzing/fuzzing_run.hpp
    ./src/fuzzing_run.cpp

    ./include/fuzzing/fuzzers_map.hpp
    ./src/fuzzers_map.cpp

    ./include/fuzzing/dump.hpp
    ./src/dump.cpp
    )

set_target_properties(${THIS_TARGET_NAME} PROPERTIES
    DEBUG_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Debug"
    RELEASE_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Release"
    RELWITHDEBINFO_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_RelWithDebInfo"
    )

install(TARGETS ${THIS_TARGET_NAME} DESTINATION "lib")
