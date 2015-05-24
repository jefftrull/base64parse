cmake_minimum_required(VERSION 2.8)
enable_testing()

# This demo actually requires a non-released version of Boost
# I grab Boost from git, check out develop, check out the develop branch
#  of the spirit submodule, then point there with BOOST_ROOT to do this build.

find_package(Boost 1.58)

add_definitions( -DBOOST_SPIRIT_USE_PHOENIX_V3=1 )
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  add_definitions( -std=c++1y -ftemplate-depth=512 -Wno-unused-local-typedefs -Wno-deprecated-declarations -g )
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  add_definitions( -std=c++14 -ftemplate-depth=512 -stdlib=libc++ )
endif()

include_directories( SYSTEM ${Boost_INCLUDE_DIRS} )

add_executable( base64 base64.cpp )
add_test( base64 base64 )
