set(THIS_TARGET_NAME fuzzing)

add_library(${THIS_TARGET_NAME}
    ./include/fuzzing/stdin_bits.hpp
    ./src/stdin_bits.cpp

    ./include/fuzzing/branching_node.hpp
    ./src/branching_node.cpp
    ./include/fuzzing/fuzzer.hpp
    ./src/fuzzer.cpp

    ./include/fuzzing/sensitivity_analysis.hpp
    ./src/sensitivity_analysis.cpp

    ./include/fuzzing/typed_minimization_analysis.hpp
    ./src/typed_minimization_analysis.cpp

    ./include/fuzzing/minimization_analysis.hpp
    ./src/minimization_analysis.cpp

    ./include/fuzzing/bitshare_analysis.hpp
    ./src/bitshare_analysis.cpp

    ./include/fuzzing/jetklee_analysis.hpp
    ./src/jetklee_analysis.cpp

    ./include/fuzzing/execution_trace.hpp
    ./src/execution_trace.cpp

    ./include/fuzzing/termination_info.hpp
    ./include/fuzzing/analysis_outcomes.hpp
    ./include/fuzzing/analysis_outcomes.hpp

    ./include/fuzzing/fuzzing_loop.hpp
    ./src/fuzzing_loop.cpp

    ./include/fuzzing/optimization_outcomes.hpp
    ./include/fuzzing/optimizer.hpp
    ./src/optimizer.cpp

    ./include/fuzzing/dump.hpp
    ./src/dump.cpp
    ./include/fuzzing/dump_native.hpp
    ./src/dump_native.cpp
    ./include/fuzzing/dump_testcomp.hpp
    ./src/dump_testcomp.cpp

    ./include/fuzzing/progress_recorder.hpp
    ./src/progress_recorder.cpp

    ./include/fuzzing/execution_record.hpp
    ./include/fuzzing/execution_record_writer.hpp
    ./src/execution_record_writer.cpp

    ./include/fuzzing/jetklee.hpp
    ./src/jetklee.cpp
    )

set_target_properties(${THIS_TARGET_NAME} PROPERTIES
    DEBUG_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Debug"
    RELEASE_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Release"
    RELWITHDEBINFO_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_RelWithDebInfo"
    )

# install(TARGETS ${THIS_TARGET_NAME} DESTINATION "lib")
