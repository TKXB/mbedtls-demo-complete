# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.7

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /opt/clion-2017.1/bin/cmake/bin/cmake

# The command to remove a file.
RM = /opt/clion-2017.1/bin/cmake/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /tmp/mbedtls-demo-complete

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /tmp/mbedtls-demo-complete/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/ecdsa_demo.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/ecdsa_demo.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/ecdsa_demo.dir/flags.make

CMakeFiles/ecdsa_demo.dir/ecdsa_demo.c.o: CMakeFiles/ecdsa_demo.dir/flags.make
CMakeFiles/ecdsa_demo.dir/ecdsa_demo.c.o: ../ecdsa_demo.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/tmp/mbedtls-demo-complete/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/ecdsa_demo.dir/ecdsa_demo.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/ecdsa_demo.dir/ecdsa_demo.c.o   -c /tmp/mbedtls-demo-complete/ecdsa_demo.c

CMakeFiles/ecdsa_demo.dir/ecdsa_demo.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ecdsa_demo.dir/ecdsa_demo.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /tmp/mbedtls-demo-complete/ecdsa_demo.c > CMakeFiles/ecdsa_demo.dir/ecdsa_demo.c.i

CMakeFiles/ecdsa_demo.dir/ecdsa_demo.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ecdsa_demo.dir/ecdsa_demo.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /tmp/mbedtls-demo-complete/ecdsa_demo.c -o CMakeFiles/ecdsa_demo.dir/ecdsa_demo.c.s

CMakeFiles/ecdsa_demo.dir/ecdsa_demo.c.o.requires:

.PHONY : CMakeFiles/ecdsa_demo.dir/ecdsa_demo.c.o.requires

CMakeFiles/ecdsa_demo.dir/ecdsa_demo.c.o.provides: CMakeFiles/ecdsa_demo.dir/ecdsa_demo.c.o.requires
	$(MAKE) -f CMakeFiles/ecdsa_demo.dir/build.make CMakeFiles/ecdsa_demo.dir/ecdsa_demo.c.o.provides.build
.PHONY : CMakeFiles/ecdsa_demo.dir/ecdsa_demo.c.o.provides

CMakeFiles/ecdsa_demo.dir/ecdsa_demo.c.o.provides.build: CMakeFiles/ecdsa_demo.dir/ecdsa_demo.c.o


CMakeFiles/ecdsa_demo.dir/util.c.o: CMakeFiles/ecdsa_demo.dir/flags.make
CMakeFiles/ecdsa_demo.dir/util.c.o: ../util.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/tmp/mbedtls-demo-complete/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/ecdsa_demo.dir/util.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/ecdsa_demo.dir/util.c.o   -c /tmp/mbedtls-demo-complete/util.c

CMakeFiles/ecdsa_demo.dir/util.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ecdsa_demo.dir/util.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /tmp/mbedtls-demo-complete/util.c > CMakeFiles/ecdsa_demo.dir/util.c.i

CMakeFiles/ecdsa_demo.dir/util.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ecdsa_demo.dir/util.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /tmp/mbedtls-demo-complete/util.c -o CMakeFiles/ecdsa_demo.dir/util.c.s

CMakeFiles/ecdsa_demo.dir/util.c.o.requires:

.PHONY : CMakeFiles/ecdsa_demo.dir/util.c.o.requires

CMakeFiles/ecdsa_demo.dir/util.c.o.provides: CMakeFiles/ecdsa_demo.dir/util.c.o.requires
	$(MAKE) -f CMakeFiles/ecdsa_demo.dir/build.make CMakeFiles/ecdsa_demo.dir/util.c.o.provides.build
.PHONY : CMakeFiles/ecdsa_demo.dir/util.c.o.provides

CMakeFiles/ecdsa_demo.dir/util.c.o.provides.build: CMakeFiles/ecdsa_demo.dir/util.c.o


# Object files for target ecdsa_demo
ecdsa_demo_OBJECTS = \
"CMakeFiles/ecdsa_demo.dir/ecdsa_demo.c.o" \
"CMakeFiles/ecdsa_demo.dir/util.c.o"

# External object files for target ecdsa_demo
ecdsa_demo_EXTERNAL_OBJECTS =

ecdsa_demo: CMakeFiles/ecdsa_demo.dir/ecdsa_demo.c.o
ecdsa_demo: CMakeFiles/ecdsa_demo.dir/util.c.o
ecdsa_demo: CMakeFiles/ecdsa_demo.dir/build.make
ecdsa_demo: CMakeFiles/ecdsa_demo.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/tmp/mbedtls-demo-complete/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable ecdsa_demo"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/ecdsa_demo.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/ecdsa_demo.dir/build: ecdsa_demo

.PHONY : CMakeFiles/ecdsa_demo.dir/build

CMakeFiles/ecdsa_demo.dir/requires: CMakeFiles/ecdsa_demo.dir/ecdsa_demo.c.o.requires
CMakeFiles/ecdsa_demo.dir/requires: CMakeFiles/ecdsa_demo.dir/util.c.o.requires

.PHONY : CMakeFiles/ecdsa_demo.dir/requires

CMakeFiles/ecdsa_demo.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/ecdsa_demo.dir/cmake_clean.cmake
.PHONY : CMakeFiles/ecdsa_demo.dir/clean

CMakeFiles/ecdsa_demo.dir/depend:
	cd /tmp/mbedtls-demo-complete/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /tmp/mbedtls-demo-complete /tmp/mbedtls-demo-complete /tmp/mbedtls-demo-complete/cmake-build-debug /tmp/mbedtls-demo-complete/cmake-build-debug /tmp/mbedtls-demo-complete/cmake-build-debug/CMakeFiles/ecdsa_demo.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/ecdsa_demo.dir/depend

