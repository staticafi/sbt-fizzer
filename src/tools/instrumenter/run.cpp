#include <instrumenter/program_info.hpp>
#include <instrumenter/program_options.hpp>
#include <instrumenter/llvm_instrumenter.hpp>
#include <utility/config.hpp>
#if COMPILER() == COMPILER_VC()
#    pragma warning(push)
#    pragma warning(disable : 4624 4996 4146 4800 4996 4005 4355 4244 4267)
#endif
#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/DebugInfo/DIContext.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/raw_os_ostream.h>
#if COMPILER() == COMPILER_VC()
#    pragma warning(pop)
#endif
#include <filesystem>
#include <memory>
#include <iostream>
#include <fstream>


void dump_dbg_mapping(
        llvm_instrumenter::instruction_dbg_info_vector const& mapping,
        llvm_instrumenter::basic_block_dbg_info_map const& bbInfo,
        std::string const& type
        )
{
    std::filesystem::path const output_dir{ std::filesystem::path(get_program_options()->value("output")).parent_path() };
    std::filesystem::path const input_file_name { std::filesystem::path(get_program_options()->value("input")).filename().replace_extension("") };
    std::filesystem::path pathname = output_dir / (input_file_name.string() + "_dbg_" + type + "_map.json");
    std::ofstream  ostr(pathname.c_str(), std::ios::binary);
    ostr << "{";
    bool started { false }; 
    for (auto const&  info : mapping) {
        if (started) ostr << ','; else started = true;
        llvm::DILocation const *dbgLoc = info.instruction->getDebugLoc();
        if (dbgLoc == nullptr)
            dbgLoc = bbInfo.at(info.instruction->getParent()).info;
        if (dbgLoc == nullptr)
        {
            std::cerr << "Retrieval of debug information for the instruction #" << info.id << "has FAILED!\n";
            continue;
        }
        ostr << '\n'
                << '"' << info.id << "\": [ "
                << dbgLoc->getLine() << ", "
                << dbgLoc->getColumn() << ", "
                << bbInfo.at(info.instruction->getParent()).id << ", "
                << info.shift
            << " ]"
                ;
    }
    ostr << "\n}\n";
}


void run(int argc, char* argv[])
{
    if (get_program_options()->has("help"))
    {
        std::cout << get_program_options() << std::endl;
        return;
    }
    if (get_program_options()->has("version"))
    {
        std::cout << get_program_options()->value("version") << std::endl;
        return;
    }
    if (!get_program_options()->has("input"))
    {
        std::cout << "No input file was specified." << std::endl;
        return;
    }
    if (!std::filesystem::is_regular_file(get_program_options()->value("input")))
    {
        std::cout << "Cannot access the input file: " << get_program_options()->value("input") << std::endl;
        return;
    }
    if (!get_program_options()->has("output"))
    {
        std::cout << "No output file was specified." << std::endl;
        return;
    }

    llvm::SMDiagnostic D;
    llvm::LLVMContext C;
    std::unique_ptr<llvm::Module> M{ llvm::parseIRFile(get_program_options()->value("input"), D, C) };
    if (M == nullptr)
    {
        llvm::raw_os_ostream ros(std::cout);
        D.print(std::filesystem::path(get_program_options()->value("input")).filename().string().c_str(),ros,false);
        ros.flush();
        return;
    }

    llvm_instrumenter  instrumenter;
    instrumenter.doInitialization(M.get());
    instrumenter.renameRedefinedStdFunctions();
    for (auto it = M->begin(); it != M->end(); ++it)
        instrumenter.runOnFunction(*it, get_program_options()->has("br_too"));

    {
        std::ofstream  ostr(get_program_options()->value("output").c_str(), std::ios::binary);
        llvm::raw_os_ostream ros(ostr);
        M->print(ros, 0);
        ros.flush();
    }

    if (get_program_options()->has("save_mapping"))
    {
        instrumenter.propagateMissingBasicBlockDbgInfo();
        dump_dbg_mapping(instrumenter.getCondInstrDbgInfo(), instrumenter.getBasicBlockDbgInfo(), "cond");
        dump_dbg_mapping(instrumenter.getBrInstrDbgInfo(), instrumenter.getBasicBlockDbgInfo(), "br");
    }
}
