set(THIS_TARGET_NAME kleeient)

set(KLEEIENT_SOURCES
    ./program_options.hpp
    ./program_options.cpp

    ./program_info.hpp
    ./program_info.cpp

    ./main.cpp
    ./run_kleeient.cpp
    )

set(KLEEIENT_LIBS
    connection
    iomodels
    instrumentation
    iomodels
    utility
    )

add_executable(${THIS_TARGET_NAME}
    ${KLEEIENT_SOURCES}
    )

target_link_libraries(${THIS_TARGET_NAME}
    ${KLEEIENT_LIBS}
    ${BOOST_LIST_OF_LIBRARIES_TO_LINK_WITH}
    )

set_target_properties(${THIS_TARGET_NAME} PROPERTIES
    DEBUG_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Debug"
    RELEASE_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Release"
    RELWITHDEBINFO_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_RelWithDebInfo"
    )

install(TARGETS ${THIS_TARGET_NAME} DESTINATION "tools")
