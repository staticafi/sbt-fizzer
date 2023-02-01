set(THIS_TARGET_NAME fuzzhamm)

add_library(${THIS_TARGET_NAME}
    ./include/fuzzhamm/fuzzer.hpp
    ./src/fuzzer.cpp

    ./include/fuzzhamm/execution_trace.hpp
    ./src/execution_trace.cpp

    ./include/fuzzhamm/execution_trace_utils.hpp
    ./src/execution_trace_utils_create_fuzzer.cpp
    ./src/execution_trace_utils_sensitive_bits.cpp
    ./src/execution_trace_utils_indices_hitcounts.cpp
    ./src/execution_trace_utils_histogram.cpp
    ./src/execution_trace_utils_classification.cpp
    ./src/execution_trace_utils_did.cpp
    ./src/execution_trace_utils_iid.cpp
    ./src/execution_trace_utils_to_json.cpp

    ./include/fuzzhamm/branching_fuzzer_base.hpp
    ./src/branching_fuzzer_base.cpp

    ./include/fuzzhamm/branching_fuzzer_sequence.hpp
    ./src/branching_fuzzer_sequence.cpp

    ./include/fuzzhamm/branching_fuzzer_extended_descent.hpp
    ./src/branching_fuzzer_extended_descent.cpp

    ./include/fuzzhamm/iid_fuzzer_base.hpp
    ./src/iid_fuzzer_base.cpp

    ./include/fuzzhamm/sensitivity_fuzzer_base.hpp
    ./src/sensitivity_fuzzer_base.cpp

    ./include/fuzzhamm/sensitivity_fuzzer_sequence.hpp
    ./src/sensitivity_fuzzer_sequence.cpp

    ./include/fuzzhamm/iid_fuzzer_improve_branching_directions.hpp
    ./src/iid_fuzzer_improve_branching_directions.cpp

    ./include/fuzzhamm/sensitivity_fuzzer_hamming.hpp
    ./src/sensitivity_fuzzer_hamming.cpp

    ./include/fuzzhamm/sensitivity_fuzzer_progress_check.hpp
    ./src/sensitivity_fuzzer_progress_check.cpp

    ./include/fuzzhamm/sensitivity_fuzzer_similar_trace_search.hpp
    ./src/sensitivity_fuzzer_similar_trace_search.cpp
    )

set_target_properties(${THIS_TARGET_NAME} PROPERTIES
    DEBUG_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Debug"
    RELEASE_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Release"
    RELWITHDEBINFO_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_RelWithDebInfo"
    )

install(TARGETS ${THIS_TARGET_NAME} DESTINATION "lib")
