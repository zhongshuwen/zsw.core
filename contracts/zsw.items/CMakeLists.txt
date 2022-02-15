add_contract(zsw.items zsw.items ${CMAKE_CURRENT_SOURCE_DIR}/src/zsw.items.cpp)

target_include_directories(zsw.items
   PUBLIC
   ${CMAKE_CURRENT_SOURCE_DIR}/include
   ${CMAKE_CURRENT_SOURCE_DIR}/../zswcore/include
   ${CMAKE_CURRENT_SOURCE_DIR}/../zsw.perms/include)

set_target_properties(zsw.items
   PROPERTIES
   RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")

#configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/ricardian/zsw.items.contracts.md.in ${CMAKE_CURRENT_BINARY_DIR}/ricardian/zsw.items.contracts.md @ONLY )

target_compile_options( zsw.items PUBLIC -R${CMAKE_CURRENT_SOURCE_DIR}/ricardian -R${CMAKE_CURRENT_BINARY_DIR}/ricardian )
