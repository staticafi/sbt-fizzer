#include <utility/config.hpp>
#if COMPILER() == COMPILER_VC()
#   pragma warning(disable:4244) // LLVM: warning C4244: 'return': conversion from 'uint64_t' to 'unsigned long', possible loss of data
#   pragma warning(disable:4267) // LLVM: warning C4267: '+=': conversion from 'size_t' to 'unsigned int', possible loss of data 
#   pragma warning(disable:4624) // LLVM: warning C4624: 'llvm::detail::copy_construction_triviality_helper<T>': destructor was implicitly defined
#   pragma warning(disable:4146) // LLVM: warning C4146: unary minus operator applied to unsigned type, result still unsigned
#endif
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include <llvm/Pass.h>
#include <algorithm>

using namespace llvm;

namespace {

struct FizzerPass : public FunctionPass {
  public:
    static char ID;

    IntegerType *Int1Ty;
    IntegerType *Int8Ty;
    IntegerType *Int16Ty;
    IntegerType *Int32Ty;
    IntegerType *Int64Ty;

    Type *VoidTy;

    Type *FloatTy;
    Type *DoubleTy;

    std::unique_ptr<legacy::FunctionPassManager> DependenciesFPM;

    FunctionCallee processCondFunc;
    FunctionCallee processCondBrFunc;
    FunctionCallee processCallBeginFunc;
    FunctionCallee processCallEndFunc;

    unsigned int basicBlockCounter;
    unsigned int condCounter;
    unsigned int callSiteCounter;

    FizzerPass() : FunctionPass(ID) {}
    void replaceCalls(
        Function &F, 
        std::unordered_map<std::string, FunctionCallee> replacements
    );
    void instrumentCalls(Function &F);
    bool runOnFunction(Function &F);

    bool doInitialization(Module &M);

    void printErrCond(Value *cond);

    void instrumentCondBr(BranchInst *brInst);
    void instrumentCond(Instruction *inst);
    Value *instrumentCmp(CmpInst *cmpInst, IRBuilder<> &builder);
    Value *instrumentIcmp(Value *lhs, Value *rhs, CmpInst *cmpInst,
                          IRBuilder<> &builder);
    Value *instrumentFcmp(Value *lhs, Value *rhs, CmpInst *cmpInst,
                          IRBuilder<> &builder);
};

} // namespace

bool FizzerPass::doInitialization(Module &M) {
    LLVMContext &C = M.getContext();

    Int1Ty = IntegerType::getInt1Ty(C);
    Int8Ty = IntegerType::getInt8Ty(C);
    Int32Ty = IntegerType::getInt32Ty(C);
    Int64Ty = IntegerType::getInt64Ty(C);

    VoidTy = Type::getVoidTy(C);

    FloatTy = Type::getFloatTy(C);
    DoubleTy = Type::getDoubleTy(C);

    DependenciesFPM = std::make_unique<legacy::FunctionPassManager>(&M);
    DependenciesFPM->add(createLowerSwitchPass());

    processCondFunc =
        M.getOrInsertFunction("__sbt_fizzer_process_condition", VoidTy,
                              Int32Ty, Int1Ty, DoubleTy);

    processCondBrFunc =
        M.getOrInsertFunction("__sbt_fizzer_process_br_instr", VoidTy,
                              Int32Ty, Int1Ty);

    processCallBeginFunc =
        M.getOrInsertFunction("__sbt_fizzer_process_call_begin", VoidTy,
                              Int32Ty);
    processCallEndFunc =
        M.getOrInsertFunction("__sbt_fizzer_process_call_end", VoidTy,
                              Int32Ty);

    basicBlockCounter = 0;
    condCounter = 0;
    callSiteCounter = 0;

    return true;
}

void FizzerPass::printErrCond(Value *cond) {
    errs() << "Condition instruction is: ";
    cond->print(errs());
    errs() << "\n";
}

Value *FizzerPass::instrumentIcmp(Value *lhs, Value *rhs, CmpInst *cmpInst,
                                  IRBuilder<> &builder) {

    // pointer comparison -> consider the distance to be 1
    if (lhs->getType()->isPointerTy()) {
        return ConstantFP::get(DoubleTy, 1);
    }

    bool isUnsigned = cmpInst->isUnsigned();

    // if the value was extended we can't overflow meaning we don't need to
    // cast to a higher type
    if (!(dyn_cast<ZExtInst>(lhs) || dyn_cast<SExtInst>(lhs) ||
            dyn_cast<ZExtInst>(rhs) || dyn_cast<SExtInst>(rhs))) {

        // extend based on the signedness
        if (isUnsigned) {
            lhs =
                builder.CreateZExt(lhs, lhs->getType()->getExtendedType());
            rhs =
                builder.CreateZExt(rhs, rhs->getType()->getExtendedType());
        }
        else {
            lhs =
                builder.CreateSExt(lhs, lhs->getType()->getExtendedType());
            rhs =
                builder.CreateSExt(rhs, rhs->getType()->getExtendedType());
        }
    }

    Value *distance = builder.CreateSub(lhs, rhs);

    if (isUnsigned) {
        return builder.CreateUIToFP(distance, DoubleTy);
    }
    return builder.CreateSIToFP(distance, DoubleTy);
}

Value *FizzerPass::instrumentFcmp(Value *lhs, Value *rhs, CmpInst *cmpInst,
                                  IRBuilder<> &builder) {
    if (lhs->getType()->isFloatTy()) {
        lhs = builder.CreateFPExt(lhs, DoubleTy);
        rhs = builder.CreateFPExt(rhs, DoubleTy);
    }

    Value *distance = builder.CreateFSub(lhs, rhs);

    if (!distance->getType()->isDoubleTy()) {
        return builder.CreateFPTrunc(distance, DoubleTy);
    }

    return distance;
}

Value *FizzerPass::instrumentCmp(CmpInst *cmpInst, IRBuilder<> &builder) {
    Value *lhs = cmpInst->getOperand(0);
    Value *rhs = cmpInst->getOperand(1);

    if (cmpInst->isIntPredicate()) {
        return instrumentIcmp(lhs, rhs, cmpInst, builder);
    }
    return instrumentFcmp(lhs, rhs, cmpInst, builder);
}


void FizzerPass::instrumentCond(Instruction *inst) {
    if (!inst->getNextNode()) {
        return;
    }
    IRBuilder<> builder(inst->getNextNode());

    Value *distance;
    if (auto *cmpInst = dyn_cast<CmpInst>(inst)) {
        distance = instrumentCmp(cmpInst, builder);
    // truncating a number to i1, happens for example with bool in C
    } else if (dyn_cast<TruncInst>(inst)) {
        distance = ConstantFP::get(DoubleTy, 1);
    // i1 as a return from a call to a function
    } else if (dyn_cast<CallInst>(inst)) {
        distance = ConstantFP::get(DoubleTy, 1);
    } else {
        return;
    }
    
    Value *location = ConstantInt::get(Int32Ty, ++condCounter);
    Value *cond = inst;

    builder.CreateCall(processCondFunc,
                {location, cond, distance});
}

void FizzerPass::instrumentCondBr(BranchInst *brInst) {
    IRBuilder<> builder(brInst);
    
    Value *location = ConstantInt::get(Int32Ty, ++basicBlockCounter);
    Value *cond = brInst->getCondition();

    builder.CreateCall(processCondBrFunc, {location, cond});
}

void FizzerPass::replaceCalls(
    Function &F,
    std::unordered_map<std::string, FunctionCallee> replacements
    ) {
    std::vector<std::pair<CallInst*, FunctionCallee>> replaceCalls;

    for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
        if (auto *callInst = dyn_cast<CallInst>(&*I)) {
            Function* callee = callInst->getCalledFunction();
            if (!callee) {
                continue;
            }
            auto it = replacements.find(callee->getName().str());
            if (it != replacements.end()) {
                replaceCalls.emplace_back(callInst, it->second);
            }
            
        }
    }
    
    for (auto [callInst, replacement]: replaceCalls) {
        ReplaceInstWithInst(callInst, CallInst::Create(replacement));
    }
}

void FizzerPass::instrumentCalls(Function &F) {
    auto const ignore = [](std::string const& name) {
        return name.find("__sbt_fizzer_") == 0 ||
               name.find("__VERIFIER_nondet_") == 0;
    };
    std::vector<CallInst*> callSites;
    for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
        if (auto *callInst = dyn_cast<CallInst>(&*I)) {
            if (callInst->getCalledFunction() != nullptr
                && !callInst->getCalledFunction()->isDeclaration()
                && callInst->getNextNode() != nullptr
                && !ignore(callInst->getCalledFunction()->getName().str())) {
                callSites.push_back(callInst);
            }
        }
    }
    for (CallInst *callInst: callSites) {
        IRBuilder<>{ callInst }.CreateCall(processCallBeginFunc,
            { ConstantInt::get(Int32Ty, ++callSiteCounter) });
        IRBuilder<>{ callInst->getNextNode() }.CreateCall(processCallEndFunc,
            { ConstantInt::get(Int32Ty, callSiteCounter) });
    }
}

bool FizzerPass::runOnFunction(Function &F) {
    if (F.isDeclaration()) {
        return false;
    }

    DependenciesFPM->run(F);

    if (F.getName() == "main") {
        F.setName("__sbt_fizzer_method_under_test");
    }

    instrumentCalls(F);

    for (BasicBlock &BB : F) {
        ++basicBlockCounter;
        BB.setName("bb" + std::to_string(basicBlockCounter));

        for (Instruction &I: BB) {
            if (I.getType() == Int1Ty) {
                instrumentCond(&I);
            }
        }

        BranchInst *brInst = dyn_cast<BranchInst>(BB.getTerminator());
        if (!brInst || !brInst->isConditional()) {
            continue;
        }
        instrumentCondBr(brInst);
    }
    return true;
}

//-----------------------------------------------------------------------------
// Legacy PM Registration
//-----------------------------------------------------------------------------
char FizzerPass::ID = 0;

static void registerFizzerPass(const PassManagerBuilder &,
                               legacy::PassManagerBase &PM) {
    PM.add(new FizzerPass());
}

static RegisterPass<FizzerPass> X("legacy-sbt-fizzer-pass",
                                  "SBT-Fizzer instrumentation pass", false, false);

static RegisterStandardPasses
    RegisterFizzerPass(PassManagerBuilder::EP_EarlyAsPossible,
                       registerFizzerPass);
