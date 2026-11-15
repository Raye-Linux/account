cmake_minimum_required(VERSION 3.24)
project(raye-account-qml LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 6.6 REQUIRED COMPONENTS Core Qml DBus Test)

qt_standard_project_setup(REQUIRES 6.6)

# org.raye.account: the RayeAccount singleton that Settings and the Store
# use to talk to raye-accountd. Loading it starts nothing; the service
# starts on the first call.
qt_add_qml_module(rayeaccount
    URI org.raye.account
    VERSION 1.0
    PLUGIN_TARGET rayeaccountplugin
    OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/qml/org/raye/account
    SOURCES rayeaccount.cpp rayeaccount.h
)
target_link_libraries(rayeaccount PUBLIC Qt6::Core Qt6::Qml PRIVATE Qt6::DBus)

include(GNUInstallDirs)
install(TARGETS rayeaccount rayeaccountplugin
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY ${CMAKE_BINARY_DIR}/qml/org/raye/account
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/qt6/qml/org/raye)

enable_testing()
qt_add_executable(test_rayeaccount tests/test_rayeaccount.cpp)
target_link_libraries(test_rayeaccount PRIVATE rayeaccount Qt6::Test Qt6::DBus)
target_include_directories(test_rayeaccount PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
add_test(NAME test_rayeaccount COMMAND dbus-run-session -- $<TARGET_FILE:test_rayeaccount>)
