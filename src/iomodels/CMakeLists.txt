set(THIS_TARGET_NAME iomodels)

add_library(${THIS_TARGET_NAME}
    ./include/iomodels/iomanager.hpp
    ./src/iomanager.cpp

    ./include/iomodels/instrumentation_callbacks.hpp
    ./src/instrumentation_callbacks.cpp

    ./include/iomodels/stdin_base.hpp

    ./include/iomodels/stdin_replay_bits_then_repeat_85.hpp
    ./src/stdin_replay_bits_then_repeat_85.cpp
    ./include/iomodels/stdin_replay_bits_then_repeat_zero.hpp
    ./src/stdin_replay_bits_then_repeat_zero.cpp

    ./include/iomodels/stdout_base.hpp

    ./include/iomodels/stdout_void.hpp
    ./src/stdout_void.cpp

    ./include/iomodels/ioexceptions.hpp
    )

set_target_properties(${THIS_TARGET_NAME} PROPERTIES
    DEBUG_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Debug"
    RELEASE_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Release"
    RELWITHDEBINFO_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_RelWithDebInfo"
    )

install(TARGETS ${THIS_TARGET_NAME} DESTINATION "lib")
