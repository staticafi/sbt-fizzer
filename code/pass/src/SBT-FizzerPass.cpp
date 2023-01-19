#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include <llvm/Pass.h>

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

    FunctionCallee processBranchFunc;
    FunctionCallee fizzerTerminate;
    FunctionCallee fizzerReachError;

    unsigned int basicBlockCount;

    FizzerPass() : FunctionPass(ID) {}
    void replaceCalls(
        Function &F, 
        std::unordered_map<std::string, FunctionCallee> replacements
    );
    bool runOnFunction(Function &F);

    bool doInitialization(Module &M);

    void printErrCond(Value *cond);

    void instrumentCondBranch(BasicBlock *bb, Value *cond, bool negateCond);
    Value *instrumentCmpBranch(CmpInst *cmpInst, IRBuilder<> &builder);
    Value *instrumentIcmp(Value *lhs, Value *rhs, CmpInst *cmpInst,
                          IRBuilder<> &builder);
    Value *instrumentFcmp(Value *lhs, Value *rhs, CmpInst *cmpInst,
                          IRBuilder<> &builder);

    CallInst *instrumentIntEq(Value *val1, Value *val2, IRBuilder<> &builder);
    CallInst *instrumentFPEq(Value *val1, Value *val2, IRBuilder<> &builder);
    std::tuple<Value *, Value *> instrumentIntIneq(Value *val1, Value *val2,
                                                   IRBuilder<> &builder);
    std::tuple<Value *, Value *> instrumentFPIneq(Value *val1, Value *val2,
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

    processBranchFunc =
        M.getOrInsertFunction("__sbt_fizzer_process_branch", VoidTy,
                              Int32Ty, Int1Ty, DoubleTy);

    fizzerTerminate = M.getOrInsertFunction("__sbt_fizzer_terminate", VoidTy);

    fizzerReachError = M.getOrInsertFunction("__sbt_fizzer_reach_error", 
                                             VoidTy);

    basicBlockCount = 0;

    return true;
}

void FizzerPass::printErrCond(Value *cond) {
    errs() << "Condition instruction is: ";
    cond->print(errs());
    errs() << "\n";
}


CallInst *FizzerPass::instrumentIntEq(Value *val1, Value *val2,
                                      IRBuilder<> &builder) {
    Value *diff = builder.CreateSub(val1, val2);
    return builder.CreateBinaryIntrinsic(Intrinsic::abs, diff,
                                         ConstantInt::get(Int1Ty, 0));
}

CallInst *FizzerPass::instrumentFPEq(Value *val1, Value *val2,
                                     IRBuilder<> &builder) {
    Value *diff = builder.CreateFSub(val1, val2);
    return builder.CreateUnaryIntrinsic(Intrinsic::fabs, diff);
}

// returns {val1 - val2, val2 - val1 + 1}
std::tuple<Value *, Value *>
FizzerPass::instrumentIntIneq(Value *val1, Value *val2, IRBuilder<> &builder) {
    Value *diff1 = builder.CreateSub(val1, val2);
    Value *diff2 = builder.CreateAdd(builder.CreateSub(val2, val1),
                                     ConstantInt::get(val1->getType(), 1));
    return {diff1, diff2};
}

// returns {val1 - val2, val2 - val1 + 1}
std::tuple<Value *, Value *>
FizzerPass::instrumentFPIneq(Value *val1, Value *val2, IRBuilder<> &builder) {
    Value *diff1 = builder.CreateFSub(val1, val2);
    Value *diff2 = builder.CreateFAdd(builder.CreateFSub(val2, val1),
                                      ConstantFP::get(val1->getType(), 1));
    return {diff1, diff2};
}

Value *FizzerPass::instrumentIcmp(Value *lhs, Value *rhs, CmpInst *cmpInst,
                                  IRBuilder<> &builder) {

    Value *valTrue = ConstantInt::get(lhs->getType(), 0);
    Value *valFalse = ConstantInt::get(lhs->getType(), 0);

    CmpInst::Predicate opcode = cmpInst->getPredicate();

    // pointer comparison -> consider the distance to be 1
    if (lhs->getType()->isPointerTy()) {
        return ConstantFP::get(DoubleTy, 1);
    } else {
        // if the value was extended we can't overflow meaning we don't need to
        // cast to a higher type
        if (!(dyn_cast<ZExtInst>(lhs) || dyn_cast<SExtInst>(lhs) ||
              dyn_cast<ZExtInst>(rhs) || dyn_cast<SExtInst>(rhs))) {

            // extend based on the signedness
            if (CmpInst::ICMP_UGT <= opcode && opcode <= CmpInst::ICMP_ULE) {
                lhs =
                    builder.CreateZExt(lhs, lhs->getType()->getExtendedType());
                rhs =
                    builder.CreateZExt(rhs, rhs->getType()->getExtendedType());
            }
            // treat values tested for equality as signed
            else {
                lhs =
                    builder.CreateSExt(lhs, lhs->getType()->getExtendedType());
                rhs =
                    builder.CreateSExt(rhs, rhs->getType()->getExtendedType());
            }
        }
    }

    switch (opcode) {
    case CmpInst::ICMP_EQ: ///< equal
        valTrue = ConstantInt::get(lhs->getType(), 1);
        valFalse = instrumentIntEq(lhs, rhs, builder);
        break;
    case CmpInst::ICMP_NE: ///< not equal
        valTrue = instrumentIntEq(lhs, rhs, builder);
        valFalse = ConstantInt::get(lhs->getType(), 1);
        break;
    case CmpInst::ICMP_UGT: ///< unsigned greater than
    case CmpInst::ICMP_SGT: ///< signed greater than
        std::tie(valTrue, valFalse) = instrumentIntIneq(lhs, rhs, builder);
        break;
    case CmpInst::ICMP_UGE: ///< unsigned greater or equal
    case CmpInst::ICMP_SGE: ///< signed greater or equal
        std::tie(valFalse, valTrue) = instrumentIntIneq(rhs, lhs, builder);
        break;
    case CmpInst::ICMP_ULT: ///< unsigned less than
    case CmpInst::ICMP_SLT: ///< signed less than
        std::tie(valTrue, valFalse) = instrumentIntIneq(rhs, lhs, builder);
        break;
    case CmpInst::ICMP_ULE: ///< unsigned less or equal
    case CmpInst::ICMP_SLE: ///< signed less or equal
        std::tie(valFalse, valTrue) = instrumentIntIneq(lhs, rhs, builder);
        break;
    default:
        break;
    }
    Value *distance = builder.CreateUIToFP(
        builder.CreateSelect(cmpInst, valTrue, valFalse), DoubleTy);

    return distance;
}

Value *FizzerPass::instrumentFcmp(Value *lhs, Value *rhs, CmpInst *cmpInst,
                                  IRBuilder<> &builder) {

    Value *valTrue = ConstantFP::get(lhs->getType(),
                                     std::numeric_limits<double>::quiet_NaN());
    Value *valFalse = ConstantFP::get(lhs->getType(),
                                      std::numeric_limits<double>::quiet_NaN());

    if (lhs->getType()->isFloatTy()) {
        lhs = builder.CreateFPExt(lhs, DoubleTy);
        rhs = builder.CreateFPExt(rhs, DoubleTy);
    }

    switch (cmpInst->getPredicate()) {
    //                             U L G E    Intuitive operation
    case CmpInst::FCMP_FALSE: ///< 0 0 0 0    Always false (always folded)
    case CmpInst::FCMP_ORD:   ///< 0 1 1 1    True if ordered (no nans)
    case CmpInst::FCMP_UNO:   ///< 1 0 0 0    True if unordered: isnan(X) |
                              ///<            isnan(Y)
    case CmpInst::FCMP_TRUE:  ///< 1 1 1 1    Always true (always folded)
        break;
    case CmpInst::FCMP_OEQ: ///< 0 0 0 1    True if ordered and equal
    case CmpInst::FCMP_UEQ: ///< 1 0 0 1    True if unordered or equal
        valTrue = ConstantFP::get(lhs->getType(), 1);
        valFalse = instrumentFPEq(lhs, rhs, builder);
        break;
    case CmpInst::FCMP_ONE: ///< 0 1 1 0    True if ordered and operands are
                            ///<            unequal
    case CmpInst::FCMP_UNE: ///< 1 1 1 0    True if unordered or not equal
        valTrue = instrumentFPEq(lhs, rhs, builder);
        valFalse = ConstantFP::get(lhs->getType(), 1);
        break;
    case CmpInst::FCMP_OGT: ///< 0 0 1 0    True if ordered and greater than
    case CmpInst::FCMP_UGT: ///< 1 0 1 0    True if unordered or greater than
        std::tie(valTrue, valFalse) = instrumentFPIneq(lhs, rhs, builder);
        break;
    case CmpInst::FCMP_OGE: ///< 0 0 1 1    True if ordered and greater than or
                            ///<            equal
    case CmpInst::FCMP_UGE: ///< 1 0 1 1    True if unordered, greater than, or
                            ///<            equal
        std::tie(valFalse, valTrue) = instrumentFPIneq(rhs, lhs, builder);
        break;
    case CmpInst::FCMP_OLT: ///< 0 1 0 0    True if ordered and less than
    case CmpInst::FCMP_ULT: ///< 1 1 0 0    True if unordered or less than
        std::tie(valTrue, valFalse) = instrumentFPIneq(rhs, lhs, builder);
        break;
    case CmpInst::FCMP_OLE: ///< 0 1 0 1    True if ordered and less than or
                            ///<            equal
    case CmpInst::FCMP_ULE: ///< 1 1 0 1    True if unordered, less than, or
                            ///<            equal
        std::tie(valFalse, valTrue) = instrumentFPIneq(lhs, rhs, builder);
        break;
    default:
        break;
    }

    Value *distance = builder.CreateSelect(cmpInst, valTrue, valFalse);

    if (!distance->getType()->isDoubleTy()) {
        return builder.CreateFPTrunc(distance, DoubleTy);
    }

    return distance;
}

Value *FizzerPass::instrumentCmpBranch(CmpInst *cmpInst, IRBuilder<> &builder) {
    Value *lhs = cmpInst->getOperand(0);
    Value *rhs = cmpInst->getOperand(1);

    if (cmpInst->isIntPredicate()) {
        return instrumentIcmp(lhs, rhs, cmpInst, builder);
    }

    return instrumentFcmp(lhs, rhs, cmpInst, builder);
}

void FizzerPass::instrumentCondBranch(BasicBlock *bb, Value *currCond, 
                                      bool negateCond) {
    // don't instrument true or false
    if (dyn_cast<ConstantInt>(currCond)) {
        return;
    }

    if (PHINode* phi = dyn_cast<PHINode>(currCond)) {
        errs() << "EXPERIMENTAL: instrumentation for phi node in " 
                << bb->getName() << "\n";
        printErrCond(currCond);
        for (unsigned int i = 0; i < phi->getNumIncomingValues(); ++i) {
            Value *predCond = phi->getIncomingValue(i);
            BasicBlock* pred = phi->getIncomingBlock(i);
            
            instrumentCondBranch(pred, predCond, negateCond);
        }
        return;
    }

    // handle xor used as not (xor cond true)
    if (BinaryOperator *binOp = dyn_cast<BinaryOperator>(currCond)) {
        if (binOp->getOpcode() == Instruction::Xor) {
            Value *prevCond = binOp->getOperand(0);
            Value *trueConst = binOp->getOperand(1);
            if (dyn_cast<ConstantInt>(trueConst)) {
                instrumentCondBranch(bb, prevCond, !negateCond);
                return;
            }
        }
    }

    IRBuilder<> brBuilder(bb->getTerminator());

    Value *distance = ConstantFP::get(DoubleTy, 
                                      std::numeric_limits<double>::max());

    if (CmpInst *cmpInst = dyn_cast<CmpInst>(currCond)) {
        distance = instrumentCmpBranch(cmpInst, brBuilder);
    }
    // truncating a number to i1, happens for example with bool in C
    else if (dyn_cast<TruncInst>(currCond)) {
        distance = ConstantFP::get(DoubleTy, 1);
    // i1 as a return from a call to a function
    } else if (dyn_cast<CallInst>(currCond)) {
        distance = ConstantFP::get(DoubleTy, 1);
    } else {
        errs() << "ERROR: instrumentation for branch condition in " 
        << bb->getName() << " is not supported" << "\n";
        printErrCond(currCond);
    }

    Value *location = ConstantInt::get(Int32Ty, basicBlockCount);

    if (negateCond) {
        currCond = brBuilder.CreateXor(currCond, ConstantInt::get(Int1Ty, 1));
    }

    brBuilder.CreateCall(processBranchFunc,
                            {location, currCond, distance});
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

bool FizzerPass::runOnFunction(Function &F) {
    if (F.isDeclaration()) {
        return false;
    }

    DependenciesFPM->run(F);
    replaceCalls(F, {{"abort", fizzerTerminate}, 
                     {"exit", fizzerTerminate},
                     {"reach_error", fizzerReachError}
                    });

    if (F.getName() == "main") {
        F.setName("__sbt_fizzer_method_under_test");
    }

    for (BasicBlock &BB : F) {
        ++basicBlockCount;
        BB.setName("bb" + std::to_string(basicBlockCount));

        BranchInst *brInst = dyn_cast<BranchInst>(BB.getTerminator());
        if (!brInst || !brInst->isConditional()) {
            continue;
        }
        Value *cond = brInst->getCondition();
        instrumentCondBranch(&BB, cond, false);
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
