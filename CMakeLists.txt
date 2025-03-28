cmake_minimum_required(VERSION 3.10)

project(forcemsaa)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(SHARED_LIB_SRC forcemsaa.c)

add_library(forcemsaa SHARED ${SHARED_LIB_SRC})
target_compile_definitions(forcemsaa PRIVATE LOG_PREFIX="forcemsaa: ")
target_link_libraries(forcemsaa PRIVATE dl)

set_target_properties(forcemsaa PROPERTIES 
	PREFIX "" 
	OUTPUT_NAME "forcemsaa"
	SUFFIX ".so"
)

install(TARGETS forcemsaa
		DESTINATION $ENV{HOME})

set(CONFIG_FILE msaaconfig)
install(FILES ${CONFIG_FILE}
		DESTINATION $ENV{HOME})

