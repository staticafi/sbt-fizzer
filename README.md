FIZZ
====

Experimentations with gray-box program fuzzing.

1. Install prerequisities
    - MS Windows 10 or later.
    - MS Visual Studio 2019 or later.
    - VCPKG
        - Make sure it is integrated with the Visual Studio.
    - Boost C++ libraries under VCPKG (in Command Prompt):
        - vcpkg install boost --triplet=x64-windows

2. Install
    - Clone the fizz's repo (in Command Prompt):
        - mkdir fizz
        - cd fizz
        - git clone https://gitlab.fi.muni.cz/qtrtik/fizz.git .

3. Building fizz
    - Run the Visual Studio.
    - Open the "fizz" folder created above.
    - Select "fizz" project, "(install)" version.
    - Build (and run) the project.
