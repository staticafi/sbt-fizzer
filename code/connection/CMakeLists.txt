set(THIS_TARGET_NAME connection)

add_library(${THIS_TARGET_NAME}
    ./include/connection/server.hpp
    ./src/server.cpp

    ./include/connection/client.hpp
    ./src/client.cpp

    ./include/connection/medium.hpp
    ./src/medium.cpp

    ./include/connection/connection.hpp
    ./src/connection.cpp

    ./include/connection/ts_queue.hpp

    ./include/connection/client_executor.hpp
    ./src/client_executor.cpp
    )

set_target_properties(${THIS_TARGET_NAME} PROPERTIES
    DEBUG_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Debug"
    RELEASE_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Release"
    RELWITHDEBINFO_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_RelWithDebInfo"
    )

install(TARGETS ${THIS_TARGET_NAME} DESTINATION "lib")
