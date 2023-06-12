cmake_minimum_required(VERSION 3.11)

include(FetchContent)
FetchContent_Declare(
  json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.2
)
FetchContent_MakeAvailable(json)

project(mercury234-emul)
find_package(Boost 1.58.0 REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})
add_executable(mercury234 main.cpp)
target_link_libraries(mercury234 ${Boost_LIBRARIES} nlohmann_json::nlohmann_json)
