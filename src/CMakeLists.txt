if(NOT DEFINED FIZZ_BUILD_ALSO_TOOLS)
    set(FIZZ_BUILD_ALSO_TOOLS "Yes" CACHE STRING "Build also tools? (Yes/No)" FORCE)
endif()
message("Build also tools: " ${FIZZ_BUILD_ALSO_TOOLS})

include_directories(
    "${PROJECT_SOURCE_DIR}/src/utility/include"
    "${PROJECT_SOURCE_DIR}/src/instrumentation/include"
    "${PROJECT_SOURCE_DIR}/src/iomodels/include"
    "${PROJECT_SOURCE_DIR}/src/connection/include"
    "${PROJECT_SOURCE_DIR}/src/benchmarks/include"
    "${PROJECT_SOURCE_DIR}/src/client/include"
    "${PROJECT_SOURCE_DIR}/src/sala/include"
    "${PROJECT_SOURCE_DIR}/src/llvmutl/include"
    )
message("Including the following libraries to the build:")
add_subdirectory(./utility)
    message("  utility")
add_subdirectory(./instrumentation)
    message("  instrumentation")
add_subdirectory(./iomodels)
    message("  iomodels")
add_subdirectory(./connection)
    message("  connection")
add_subdirectory(./sala)
    message("  sala")
add_subdirectory(./llvmutl)
    message("  llvmutl")

if(FIZZ_BUILD_ALSO_TOOLS STREQUAL "Yes")
    include_directories(
        "${PROJECT_SOURCE_DIR}/src/fuzzing/include"
        "${PROJECT_SOURCE_DIR}/src/tools"
        "${PROJECT_SOURCE_DIR}/src/tools/salac"
        "${PROJECT_SOURCE_DIR}/src/tools/salat"
        )
    add_subdirectory(./fuzzing)
        message("  fuzzing")
    add_subdirectory(./tools)
endif()
