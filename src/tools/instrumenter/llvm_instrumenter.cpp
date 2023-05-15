#include <instrumenter/llvm_instrumenter.hpp>
#if COMPILER() == COMPILER_VC()
#   pragma warning(disable:4244) // LLVM: warning C4244: 'return': conversion from 'uint64_t' to 'unsigned long', possible loss of data
#   pragma warning(disable:4267) // LLVM: warning C4267: '+=': conversion from 'size_t' to 'unsigned int', possible loss of data 
#   pragma warning(disable:4624) // LLVM: warning C4624: 'llvm::detail::copy_construction_triviality_helper<T>': destructor was implicitly defined
#   pragma warning(disable:4146) // LLVM: warning C4146: unary minus operator applied to unsigned type, result still unsigned
#endif
#include <algorithm>

using namespace llvm;

bool llvm_instrumenter::doInitialization(Module &M) {
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

    fizzerTerminate = M.getOrInsertFunction("__sbt_fizzer_terminate", VoidTy);

    fizzerReachError = M.getOrInsertFunction("__sbt_fizzer_reach_error", 
                                             VoidTy);

    basicBlockCounter = 0;
    condCounter = 0;
    callSiteCounter = 0;

    return true;
}

void llvm_instrumenter::printErrCond(Value *cond) {
    errs() << "Condition instruction is: ";
    cond->print(errs());
    errs() << "\n";
}

Value *llvm_instrumenter::instrumentIcmp(Value *lhs, Value *rhs, CmpInst *cmpInst,
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

Value *llvm_instrumenter::instrumentFcmp(Value *lhs, Value *rhs, CmpInst *cmpInst,
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

Value *llvm_instrumenter::instrumentCmp(CmpInst *cmpInst, IRBuilder<> &builder) {
    Value *lhs = cmpInst->getOperand(0);
    Value *rhs = cmpInst->getOperand(1);

    if (cmpInst->isIntPredicate()) {
        return instrumentIcmp(lhs, rhs, cmpInst, builder);
    }
    return instrumentFcmp(lhs, rhs, cmpInst, builder);
}


void llvm_instrumenter::instrumentCond(Instruction *inst) {
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

void llvm_instrumenter::instrumentCondBr(BranchInst *brInst) {
    IRBuilder<> builder(brInst);
    
    Value *location = ConstantInt::get(Int32Ty, ++basicBlockCounter);
    Value *cond = brInst->getCondition();

    builder.CreateCall(processCondBrFunc, {location, cond});
}

void llvm_instrumenter::replaceCalls(
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

void llvm_instrumenter::instrumentCalls(Function &F) {
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

bool llvm_instrumenter::runOnFunction(Function &F) {
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
