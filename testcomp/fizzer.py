import benchexec.tools.template
import benchexec.result as result

class Tool(benchexec.tools.template.BaseTool2):
    """
    Tool info for fizzer
    """

    REQUIRED_PATHS = []
    """
    List of path patterns that is used by the default implementation of program_files().
    Not necessary if this method is overwritten.
    """

    def name(self):
        """
        Return the name of the tool, formatted for humans.
        This method always needs to be overriden, and typically just contains
        return "My Toolname"
        @return a non-empty string
        """
        return "fizzer"

    def executable(self, tool_locator):
        """
        Find the path to the executable file that will get executed.
        This method always needs to be overridden,
        and should typically delegate to our utility method find_executable. Example:
        return tool_locator.find_executable("mytool")
        The path returned should be relative to the current directory.
        @param tool_locator: an instance of class ToolLocator
        @return a string pointing to an executable file
        """
        return tool_locator.find_executable("fizzer", subdir="tools")

    def version(self, executable):
        """
        Determine a version string for this tool, if available.
        Do not hard-code a version in this function, either extract the version
        from the tool or do not return a version at all.
        There is a helper function `self._version_from_tool`
        that should work with most tools, you only need to extract the version number
        from the returned tool output.
        @return a (possibly empty) string
        """
        return ""

    def program_files(self, executable):
        """
        OPTIONAL, this method is only necessary for situations when the benchmark environment
        needs to know all files belonging to a tool
        (to transport them to a cloud service, for example).
        Returns a list of files or directories that are necessary to run the tool,
        relative to the current directory.
        The default implementation returns a list with the executable itself
        and all paths that result from expanding patterns in self.REQUIRED_PATHS,
        interpreting the latter as relative to the directory of the executable.
        @return a list of paths as strings
        """
        return [executable] + self._program_files_from_executable(
            executable, self.REQUIRED_PATHS
        )

    def cmdline(self, executable, options, task, rlimits):
        """
        Compose the command line to execute from the name of the executable,
        the user-specified options, and the inputfile to analyze.
        This method can get overridden, if, for example, some options should
        be enabled or if the order of arguments must be changed.
        All paths passed to this method (executable and fields of task)
        are either absolute or have been made relative to the designated working directory.
        @param executable: the path to the executable of the tool (typically the result of executable())
        @param options: a list of options, in the same order as given in the XML-file.
        @param task: An instance of of class Task, e.g., with the input files
        @param rlimits: An instance of class ResourceLimits with the limits for this run
        @return a list of strings that represent the command line to execute
        """
        if "--max_seconds" not in options and rlimits.cputime:
            max_seconds = rlimits.cputime - 5
            options = options + ["--max_seconds", str(max_seconds)]
        return [executable, *task.input_files_or_identifier, *options]

    def determine_result(self, run):
        """
        Parse the output of the tool and extract the verification result.
        If the tool gave a result, this method needs to return one of the
        benchexec.result.RESULT_* strings.
        Otherwise an arbitrary string can be returned that will be shown to the user
        and should give some indication of the failure reason
        (e.g., "CRASH", "OUT_OF_MEMORY", etc.).
        For tools that do not output some true/false result, benchexec.result.RESULT_DONE
        can be returned (this is also the default implementation).
        BenchExec will then automatically add some more information
        if the tool was killed due to a timeout, segmentation fault, etc.
        @param run: information about the run as instanceof of class Run
        @return a non-empty string, usually one of the benchexec.result.RESULT_* constants
        """
        if not run.output:
            return "error (no output)"

        for line in run.output:
            line = line.strip()
            if line.startswith("Fuzzing early"):
                # remove Details:
                line = line.split(". ")[0]
                if line.startswith("Unknown"):
                    return "error (client crash)"
                if line.endswith("invariant failure"):
                    return "error (invariant failure)"
                if line.endswith("assumption failure"):
                    return "error (assumption failure)"
                if line.endswith("construction"):
                    return "error (code under construction)"
                return "error (exception)"

            if not line.startswith("Termination reason:"):
                continue
            reason = line.split(": ")[1]
            if reason.startswith("Max number of seconds"):
                return result.RESULT_DONE + " (max seconds reached)"
            if reason.startswith("Max"):
                return result.RESULT_DONE + " (max executions reached)"
            if reason.startswith("The"):
                return result.RESULT_DONE + " (strategy finished)"
            return result.RESULT_DONE

        return result.RESULT_ERROR

    def get_value_from_output(self, output, identifier):
        """
        OPTIONAL, extract a statistic value from the output of the tool.
        This value will be added to the resulting tables.
        It may contain HTML code, which will be rendered appropriately in the HTML tables.
        Note that this method may be called without any of the other methods called
        before it and without any existing installation of the tool on this machine
        (because table-generator uses this method).
        @param output: The output of the tool as instance of class RunOutput.
        @param identifier: The user-specified identifier for the statistic item.
        @return a (possibly empty) string, optional with HTML tags
        """
        pass