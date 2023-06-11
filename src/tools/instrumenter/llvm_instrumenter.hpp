#ifndef TOOL_INSTRUMENTER_LLVM_INSTRUMENTER_HPP_INCLUDED
#   define TOOL_INSTRUMENTER_LLVM_INSTRUMENTER_HPP_INCLUDED

#   include <utility/config.hpp>

#   if COMPILER() == COMPILER_VC()
#       pragma warning(push)
#      pragma warning(disable:4244) // LLVM: warning C4244: 'return': conversion from 'uint64_t' to 'unsigned long', possible loss of data
#      pragma warning(disable:4267) // LLVM: warning C4267: '+=': conversion from 'size_t' to 'unsigned int', possible loss of data 
#      pragma warning(disable:4624) // LLVM: warning C4624: 'llvm::detail::copy_construction_triviality_helper<T>': destructor was implicitly defined
#      pragma warning(disable:4146) // LLVM: warning C4146: unary minus operator applied to unsigned type, result still unsigned
#      pragma warning(disable:4996) // LLVM: warning C4996: '_Header_ciso646': warning STL4036: <ciso646> is removed in C++20.
#   endif
#   include <llvm/IR/IRBuilder.h>
#   include <llvm/IR/LegacyPassManager.h>
#   include <llvm/Passes/PassBuilder.h>
#   include <llvm/Passes/PassPlugin.h>
#   include <llvm/Support/raw_ostream.h>
#   include <llvm/Transforms/IPO/PassManagerBuilder.h>
#   include <llvm/Transforms/Utils.h>
#   include <llvm/Transforms/Utils/BasicBlockUtils.h>
#   include <llvm/Pass.h>
#   if COMPILER() == COMPILER_VC()
#       pragma warning(pop)
#   endif
#   include <algorithm>
#   include <unordered_map>
#   include <vector>


struct llvm_instrumenter {

    llvm::IntegerType *Int1Ty;
    llvm::IntegerType *Int8Ty;
    llvm::IntegerType *Int16Ty;
    llvm::IntegerType *Int32Ty;
    llvm::IntegerType *Int64Ty;

    llvm::Type *VoidTy;

    llvm::Type *FloatTy;
    llvm::Type *DoubleTy;

    std::unique_ptr<llvm::legacy::FunctionPassManager> DependenciesFPM;

    llvm::FunctionCallee processCondFunc;
    llvm::FunctionCallee processCondBrFunc;
    llvm::FunctionCallee processCallBeginFunc;
    llvm::FunctionCallee processCallEndFunc;

    unsigned int basicBlockCounter;
    unsigned int condCounter;
    unsigned int callSiteCounter;

    struct basic_block_dbg_info {
        static int constexpr invalid_depth = std::numeric_limits<int>::max();
        unsigned int id { 0U };
        llvm::DILocation const *info { nullptr };
        int depth { invalid_depth };
    };

    using basic_block_dbg_info_map = std::unordered_map<llvm::BasicBlock const*, basic_block_dbg_info>;

    basic_block_dbg_info_map basicBlockDbgInfo;

    struct instruction_dbg_info {
        llvm::Instruction const *instruction { nullptr };
        unsigned int id { 0U };
        unsigned int shift { 0U };
    };

    using instruction_dbg_info_vector = std::vector<instruction_dbg_info>;

    instruction_dbg_info_vector condInstrDbgInfo;
    instruction_dbg_info_vector brInstrDbgInfo;

    void replaceCalls(
        llvm::Function &F, 
        std::unordered_map<std::string, llvm::FunctionCallee> replacements
    );
    void instrumentCalls(llvm::Function &F);
    bool runOnFunction(llvm::Function &F);

    bool doInitialization(llvm::Module &M);

    void printErrCond(llvm::Value *cond);

    void instrumentCondBr(llvm::BranchInst *brInst);
    bool instrumentCond(llvm::Instruction *inst);
    llvm::Value *instrumentCmp(llvm::CmpInst *cmpInst, llvm::IRBuilder<> &builder);
    llvm::Value *instrumentIcmp(llvm::Value *lhs, llvm::Value *rhs, llvm::CmpInst *cmpInst,
                          llvm::IRBuilder<> &builder);
    llvm::Value *instrumentFcmp(llvm::Value *lhs, llvm::Value *rhs, llvm::CmpInst *cmpInst,
                          llvm::IRBuilder<> &builder);

    void propagateMissingBasicBlockDbgInfo();
};


#endif
