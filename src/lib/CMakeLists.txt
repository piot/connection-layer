# generated by cmake-generator
cmake_minimum_required(VERSION 3.16.3)

add_library(connection-layer STATIC 
  incoming.c
  outgoing.c)

include(Tornado.cmake)
set_tornado(connection-layer)

target_include_directories(connection-layer PUBLIC ../include)


target_link_libraries(connection-layer PUBLIC 
  flood
  mash)

