# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "Debug")
  file(REMOVE_RECURSE
  "CMakeFiles\\fileSec_autogen.dir\\AutogenUsed.txt"
  "CMakeFiles\\fileSec_autogen.dir\\ParseCache.txt"
  "fileSec_autogen"
  )
endif()
