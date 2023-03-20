# **SBT-Fizzer**

The name is an acronym, where `SBT` stands for `Symbiotic`
https://github.com/staticafi/symbiotic, and `Fizzer` is
a mixture of `FI` representing our faculty and `fuzzer`.

**SBT-Fizzer** is a codebase and playground for students
interested in dynamic program analysis and gray-box fuzzing in
particular.

## License

**SBT-Fizzer** is available under the **zlib** license. It is included as 
file `LICENSE.txt` into the repository: https://github.com/staticafi/sbt-fizzer-private

## Target platforms

The primary target platform is PC running either Windows 10 (or later) or Ubuntu
22.04 (or later) operating systems.

**NOTE**: Although **SBT-Fizzer** can be built the Windows 10,
there are still issues running LLVM instrumentation. So, using 
the project under Windows  is still under construction.

## Software dependencies

The following software must be installed on your computer before you can
start with the **age** project:
- **git** distributed version control system: https://git-scm.com/
    - (optional) Configure your git in a console using these commands: 
        ```
        git config --global user.name "Your name"
        git config --global user.email "Your email"
        git config --global core.autocrlf false
        git config --global core.filemode false
        git config --global color.ui true
        ```
- **C++ compiler** supporting at least **C++20** standard:
    - On Ubuntu use one of these two options:
        - **Clang**: https://clang.llvm.org/ and https://en.wikipedia.org/wiki/Clang
        - NOTE: Consider using this command for installing the compiler:
            ```
            sudo apt install clang
            ```
    - On Windows use the **Microsoft C++** compiler and debugger:
        1. Go to page: https://visualstudio.microsoft.com/downloads/#other
        2. Search for **Tools for Visual Studio 2022** and click on the text to open nested items.
        3. Search for **Build Tools for Visual Studio 2022** nested item and click on the
           **Download** button.
- **CMake** build system: https://cmake.org/
  - NOTE: On Ubuntu consider using this command:
    ```
    sudo apt install make cmake ninja-build
    ```
- **vcpkg** software package manager: https://github.com/microsoft/vcpkg
  - Once you have the package manager installed, install into it required packages:
    ```
    vcpkg install boost llvm[core]
    ```
    On Windows append the option `--triplet=x64-windows` to the command and `--triplet=x64-linux` on Ubuntu.
- **Microsoft Visual Studio Code** (VS code) source-code editor: https://code.visualstudio.com/
    - Once you have the editor installed, install into it these extensions:
        - **C/C++** by Microsoft: https://github.com/microsoft/vscode-cpptools
        - **C/C++ Extension Pack** by Microsoft: https://github.com/microsoft/vscode-cpptools
        - **C/C++ Themes** by Microsoft: https://marketplace.visualstudio.com/items?itemName=ms-vscode.cpptools-themes
        - **CMake Tools** by Microsoft: https://github.com/microsoft/vscode-cmake-tools
        - (optional) **CMake** by twxs: https://github.com/twxs/vs.language.cmake
        - (optional) **Git Graph** by mhutchie: https://github.com/mhutchie/vscode-git-graph
        - (optional) **Code Spell Checker** by Street Side Software: https://github.com/streetsidesoftware/vscode-spell-checker
        - (optional) **Graphviz Interactive Preview** by tintinweb: https://marketplace.visualstudio.com/items?itemName=tintinweb.graphviz-interactive-preview
    - It is common and useful to use `launch.json` config file for launching an
        executable. That way you can specify command-line parameters for the
        executable. The initial (minimal) version is under `setup` folder. You
        only need to copy the file from the `setup` folder to the folder
        `.vscode` (create this folder, if it does not exist).
    - The `setup` folder also contains `tasks.json` providing useful executable
        tasks, e.g., building benchmarks and killing non-terminating clients.
        You only need to copy the file from the `setup` folder to the folder
        `.vscode` folder.
- (optional) **SmartGit** Git GUI client: https://www.syntevo.com/smartgit/

## Downloading **SBT-Fizzer**

We do not provide **SBT-Fizzer** in binary form. That means you must
download the source code and then build it.

The recommended way how to obtain source code is via `Git`. You can
either clone or fork **SBT-Fizzer**'s repository. Cloning is recommended for
a member of **SBT-Fizzer** project with Developer rights. Forking is then for
everyone else. Both procedures are described is subsections below.

NOTE: Alternatively, you can also download a ZIP package with the source
code from the projects web: https://github.com/staticafi/sbt-fizzer-private

### Cloning

Create a new directory on the disk for **SBT-Fizzer**. Let `<SBT-Fizzer-root-dir>`
be the full path to that directory. Now open the console and type
there these commands:
```
cd <SBT-Fizzer-root-dir>
git clone https://github.com/staticafi/sbt-fizzer-private.git .
```

### Forking

First you need to go to GitHub and make a fork of **SBT-Fizzer** project:
- Go to https://github.com/staticafi/sbt-fizzer-private
- Click on the **Fork** button at the upper-right corner of the page.
- Put in all information requested in the form.
- Click on the **Create fork** button.

Now clone the forked project. The procedure is the same as in the `Cloning`
subsection above, except the URL in the `git clone` command, which must
reference your forked repository.

## Integrating **vcpkg**

Before we can build **SBT-Fizzer** in VS Code, we must let VS Code to know
where is **vcpkg** installed (because it contains SW packages **SBT-Fizzer**
needs during the build process). We must create file

```
<SBT-Fizzer-root-dir>/.vscode/settings.json
```

with this content:

```
{
    "cmake.configureSettings": {
        "CMAKE_TOOLCHAIN_FILE": "<vcpkg-install-dir>/scripts/buildsystems/vcpkg.cmake",
        "CMAKE_BUILD_TYPE": "${buildType}"
    }
}
```
where `<vcpkg-install-dir>` must be replaced by the actuall installation directory of **vcpkg**.

NOTE: When working on Windows, VS Code may have created a "global" 
settings file here:
```
<user-dir>/AppData/Roaming/Code/User/settings.json
```
Instead of creating the new settings file as described above, you
can just update this existing "global" setting file by adding the section:
```
    "cmake.configureSettings": {
        "CMAKE_TOOLCHAIN_FILE": "<vcpkg-install-dir>/scripts/buildsystems/vcpkg.cmake",
        "CMAKE_BUILD_TYPE": "${buildType}"
    }
```
The advantage of this approach is, that the **vcpkg** integration
to VS Code would work for all CMake C++ projects on your computer
(including **SBT-Fizzer** of course).

## Building **SBT-Fizzer**

Open **Microsoft Visual Studio Code** and in the main menu choose:
`File/Open Folder...` and open the **SBT-Fizzer**'s directory `<SBT-Fizzer-root-dir>`.

Now you should be able to build **SBT-Fizzer** the same way as any other
CMake C++ application. All needed information are available here:
https://code.visualstudio.com/docs/cpp/introvideos-cpp

Once you successfully build the `install` target, then you can find
the built binaries under the `dist` directory.

## Usage

You can use the compiled binaries either via VS Code or manually in terminal.

### **Running binaries in VS Code**

First you need to build benchmark(s). So, go to the debugger
tab (Ctrl+Shift+D) and select the target `Benman @ dbg`.
Then press F5 to start benchmark building. By editing this
target in `launch.json` file under `.vscode` folder you can
specify what benchmarks to actually build. By default there
is set `all` meaning that all benchmarks are compiled.

Now you can debug the fuzzer (server). In the debugger tab
select the target `run server`. Then press F5 to start debugging.
By editing this target in `launch.json` file under `.vscode` 
folder you can specify what benchmark we be analysed during the
debug session. By default there is set one randomly choosen 
benchmark.

### **Running binaries in terminal**

The scripts/binaries are found in `dist/tools`

Instrumenting the target program:

`sbt-fizzer_instrument [-h] [--output_dir OUTPUT_DIR] target_file`

Building the client:

`sbt-fizzer_build_client [-h] [--output_dir OUTPUT_DIR] [--no_instrument | --instrument FLAGS] target_file`

Instrumenting, building, and running fuzzing in one:

`sbt-fizzer [-h] [--output_dir OUTPUT_DIR] [--no_instrument | --instrument FLAGS] [--clang FLAGS] [--max_seconds SECONDS] target_file`
