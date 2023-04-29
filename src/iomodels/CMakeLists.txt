set(THIS_TARGET_NAME iomodels)

add_library(${THIS_TARGET_NAME}

./include/iomodels/iomanager.hpp
    ./src/iomanager.cpp

    ./include/iomodels/stdin_base.hpp

    ./include/iomodels/stdin_replay_bytes_then_repeat_byte.hpp
    ./src/stdin_replay_bytes_then_repeat_byte.cpp
    
    ./include/iomodels/models_map.hpp
    ./src/models_map.cpp
    
    ./include/iomodels/stdout_base.hpp
    
    ./include/iomodels/stdout_void.hpp
    ./src/stdout_void.cpp

    ./include/iomodels/configuration.hpp
    ./src/configuration.cpp
    
    ./include/iomodels/ioexceptions.hpp
    )

set_target_properties(${THIS_TARGET_NAME} PROPERTIES
    DEBUG_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Debug"
    RELEASE_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Release"
    RELWITHDEBINFO_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_RelWithDebInfo"
    )

install(TARGETS ${THIS_TARGET_NAME} DESTINATION "lib")
