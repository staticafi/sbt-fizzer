set(THIS_TARGET_NAME connection)

add_library(${THIS_TARGET_NAME}
    ./include/connection/server.hpp
    ./src/server.cpp

    ./include/connection/client.hpp
    ./src/client.cpp

    ./include/connection/message.hpp
    ./src/message.cpp

    ./include/connection/connection.hpp
    ./src/connection.cpp

    ./include/connection/ts_queue.hpp

    ./include/connection/client_executor.hpp
    ./src/client_executor.cpp

    ./include/connection/kleeient.hpp
    ./src/kleeient.cpp

    ./include/connection/kleeient_connector.hpp
    ./src/kleeient_connector.cpp
    )

# libdl is required for BOOST.DLL
target_link_libraries(${THIS_TARGET_NAME} ${CMAKE_DL_LIBS} ${Boost_LIBRARIES})

set_target_properties(${THIS_TARGET_NAME} PROPERTIES
    DEBUG_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Debug"
    RELEASE_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Release"
    RELWITHDEBINFO_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_RelWithDebInfo"
    )

install(TARGETS ${THIS_TARGET_NAME} DESTINATION "lib")
