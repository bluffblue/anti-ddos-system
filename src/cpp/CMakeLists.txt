cmake_minimum_required(VERSION 3.10)
project(PacketAnalyzer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(packet_analyzer SHARED
    packet_analyzer.cpp
    packet_analyzer.h
)

set_target_properties(packet_analyzer PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)

install(TARGETS packet_analyzer
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
) 