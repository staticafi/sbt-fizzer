Contents
========

This README.md file describes the content of the tool, i.e., what is in this 
directory and sub-directories.

The license under which this tool is released is in the file ./LICENSE.txt.

The script ./sbt-fizzer.py provides a user friendly interface to the entire
tool. Use the help command
```
    python3 ./sbt-fizzer.py --help
```
to see the usage. For example, you can run the tool from any directory on a 
`C` program with the default options using the following command:
```
    python3 path/to/sbt-fizzer.py --input_file path/to/input/file.c --output_dir path/to/output/dir
```
The output directory is created, if it does not exist. Otherwise, its content
is overwritten. The generated test are stored in `JSON` format by default. You
can get tests in `XML` format, if you add option `--test_type testcomp` to the
 command line above.

The sub-directories `lib` and `lib32` contain static libraries, which are
linked to the analyzed program, after its compilation, using `Clang` compiler,
to `LLVM` bit-code. In `lib32` there are 32-bit versions of the libraries in
`lib`. The analyzed C program is assumed to be 64-bit by default. If you want
it built as 32-bit application, then add the option `--m32` to the command line.

The directory `tools` contains three 64-bit binaries. The binary starting with 
`sbt-fizzer_instrumenter_*` is used for injection of execution monitoring 
instruction into the analyzed binary program, The binary`sbt-fizzer_server_*`
is the actual analyzer. The binary `sbt-fizzer_client_*` provides an alternative
type of communication between the server and the binary of the analyzed program,
which is the network communication. The default type of communication is via
shared memory.

The source code of the tool is available here: https://github.com/staticafi/sbt-fizzer