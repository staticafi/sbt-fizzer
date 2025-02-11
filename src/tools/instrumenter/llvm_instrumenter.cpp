#include <instrumenter/llvm_instrumenter.hpp>
#if COMPILER() == COMPILER_VC()
#   pragma warning(disable:4244) // LLVM: warning C4244: 'return': conversion from 'uint64_t' to 'unsigned long', possible loss of data
#   pragma warning(disable:4267) // LLVM: warning C4267: '+=': conversion from 'size_t' to 'unsigned int', possible loss of data 
#   pragma warning(disable:4624) // LLVM: warning C4624: 'llvm::detail::copy_construction_triviality_helper<T>': destructor was implicitly defined
#   pragma warning(disable:4146) // LLVM: warning C4146: unary minus operator applied to unsigned type, result still unsigned
#endif
#include <llvm/IR/InstIterator.h>
#include <utility/timeprof.hpp>
#include <algorithm>
#include <unordered_set>

using namespace llvm;

bool llvm_instrumenter::doInitialization(Module *M) {
    TMPROF_BLOCK();

    module = M;

    LLVMContext &C = module->getContext();

    Int1Ty = IntegerType::getInt1Ty(C);
    Int8Ty = IntegerType::getInt8Ty(C);
    Int32Ty = IntegerType::getInt32Ty(C);
    Int64Ty = IntegerType::getInt64Ty(C);

    VoidTy = Type::getVoidTy(C);

    FloatTy = Type::getFloatTy(C);
    DoubleTy = Type::getDoubleTy(C);

    DependenciesFPM = std::make_unique<legacy::FunctionPassManager>(module);
    DependenciesFPM->add(createLowerSwitchPass());

    processCondFunc =
        module->getOrInsertFunction("__sbt_fizzer_process_condition", VoidTy,
                              Int32Ty, Int1Ty, DoubleTy, Int1Ty, Int8Ty);

    processCondBrFunc =
        module->getOrInsertFunction("__sbt_fizzer_process_br_instr", VoidTy,
                              Int32Ty, Int1Ty);

    processCallBeginFunc =
        module->getOrInsertFunction("__sbt_fizzer_process_call_begin", VoidTy,
                              Int32Ty);
    processCallEndFunc =
        module->getOrInsertFunction("__sbt_fizzer_process_call_end", VoidTy,
                              Int32Ty);

    basicBlockCounter = 0;
    condCounter = 0;
    callSiteCounter = 0;

    return true;
}

void llvm_instrumenter::renameFunctions()
{
    TMPROF_BLOCK();

    std::string const  renamePrefix{ "__fizzer_rename_prefix__" };
    for (auto it = module->begin(); it != module->end(); ++it)
    {
        Function&  fn = *it;
        if (!fn.isDeclaration() && fn.getName() != "main")
            fn.setName(renamePrefix + fn.getName());
    }
}

void llvm_instrumenter::printErrCond(Value *cond) {
    errs() << "Condition instruction is: ";
    cond->print(errs());
    errs() << "\n";
}

Value *llvm_instrumenter::instrumentIcmp(Value *lhs, Value *rhs, CmpInst *cmpInst,
                                  IRBuilder<> &builder) {
    if (lhs->getType()->isPointerTy() && rhs->getType()->isPointerTy())
    {
        llvm::ConstantPointerNull* const  val = llvm::ConstantPointerNull::get(llvm::cast<llvm::PointerType>(lhs->getType()));
        if (val == lhs || val == rhs)
        {
            Value* value = cmpInst->getPredicate() == llvm::CmpInst::Predicate::ICMP_EQ ? builder.CreateXor(cmpInst, 1) : cmpInst;
            return builder.CreateUIToFP(builder.CreateZExt(value, Int32Ty), DoubleTy);
        }
    }

    if (lhs->getType()->isPointerTy())
        lhs = builder.CreatePtrToInt(lhs, Int64Ty);
    if (rhs->getType()->isPointerTy())
        rhs = builder.CreatePtrToInt(rhs, Int64Ty);

    if (cmpInst->isUnsigned())
    {
        if (lhs->getType()->isIntegerTy())
            lhs = builder.CreateUIToFP(lhs, DoubleTy);
        if (rhs->getType()->isIntegerTy())
            rhs = builder.CreateUIToFP(rhs, DoubleTy);
    }
    else
    {
        if (lhs->getType()->isIntegerTy())
            lhs = builder.CreateSIToFP(lhs, DoubleTy);
        if (rhs->getType()->isIntegerTy())
            rhs = builder.CreateSIToFP(rhs, DoubleTy);
    }
    
    return instrumentFcmp(lhs, rhs, nullptr, builder);
}

Value *llvm_instrumenter::instrumentFcmp(Value *lhs, Value *rhs, CmpInst *,
                                  IRBuilder<> &builder) {
    if (lhs->getType()->isFloatTy())
        lhs = builder.CreateFPExt(lhs, DoubleTy);
    if (rhs->getType()->isFloatTy())
        rhs = builder.CreateFPExt(rhs, DoubleTy);

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


bool llvm_instrumenter::instrumentCond(Instruction *inst, bool const xor_like_branching_function) {
    if (!inst->getNextNode()) {
        return false;
    }
    IRBuilder<> builder(inst->getNextNode());

    // We emulate the 'enum BRANCHING_PREDICATE' (see instrumentation_types.hpp) as follows: 
    natural_8_bit constexpr BP_EQUAL{ 0 };
    natural_8_bit constexpr BP_UNEQUAL{ 1 };
    natural_8_bit constexpr BP_LESS{ 2 };
    natural_8_bit constexpr BP_LESS_EQUAL{ 3 };
    natural_8_bit constexpr BP_GREATER{ 4 };
    natural_8_bit constexpr BP_GREATER_EQUAL{ 5 };
    natural_8_bit predicate{ BP_UNEQUAL };

    Value *distance;
    if (auto *cmpInst = dyn_cast<CmpInst>(inst)) {
        distance = instrumentCmp(cmpInst, builder);
        switch (cmpInst->getPredicate())
        {
            case llvm::CmpInst::Predicate::FCMP_OEQ:
            case llvm::CmpInst::Predicate::FCMP_UEQ:
            case llvm::CmpInst::Predicate::ICMP_EQ:
                predicate = BP_EQUAL;
                break;
            case llvm::CmpInst::Predicate::FCMP_OGT:
            case llvm::CmpInst::Predicate::FCMP_UGT:
            case llvm::CmpInst::Predicate::ICMP_UGT:
            case llvm::CmpInst::Predicate::ICMP_SGT:
                predicate = BP_GREATER;
                break;
            case llvm::CmpInst::Predicate::FCMP_OGE:
            case llvm::CmpInst::Predicate::FCMP_UGE:
            case llvm::CmpInst::Predicate::ICMP_UGE:
            case llvm::CmpInst::Predicate::ICMP_SGE:
                predicate = BP_GREATER_EQUAL;
                break;
            case llvm::CmpInst::Predicate::FCMP_OLT:
            case llvm::CmpInst::Predicate::FCMP_ULT:
            case llvm::CmpInst::Predicate::ICMP_ULT:
            case llvm::CmpInst::Predicate::ICMP_SLT:
                predicate = BP_LESS;
                break;
            case llvm::CmpInst::Predicate::FCMP_OLE:
            case llvm::CmpInst::Predicate::FCMP_ULE:
            case llvm::CmpInst::Predicate::ICMP_ULE:
            case llvm::CmpInst::Predicate::ICMP_SLE:
                predicate = BP_LESS_EQUAL;
                break;
            case llvm::CmpInst::Predicate::FCMP_ONE:
            case llvm::CmpInst::Predicate::FCMP_UNE:
            case llvm::CmpInst::Predicate::ICMP_NE:
                predicate = BP_UNEQUAL;
                break;

            case llvm::CmpInst::Predicate::FCMP_UNO: // TODO: "is_nan" - what to do with that?
            default:
                break;
        }
    // truncating a number to i1, happens for example with bool in C
    } else if (auto* trunc = dyn_cast<TruncInst>(inst)) {
        bool  used_in_br{ false };
        for (auto  it = trunc->user_begin(); it != trunc->user_end(); ++it)
            if (isa<BranchInst>(*it))
            {
                used_in_br = true;
                break;
            }
        if (!used_in_br)
            return false;
        distance = builder.CreateUIToFP(builder.CreateZExt(inst, Int32Ty), DoubleTy);
    } else if (auto* call = dyn_cast<CallInst>(inst)) {
        if (call->getCalledOperand() == nullptr
                || dyn_cast<llvm::Function>(call->getCalledOperand()) == nullptr
                || dyn_cast<llvm::Function>(call->getCalledOperand())->getName().str() == "__VERIFIER_nondet_bool")
            return false;
        distance = builder.CreateUIToFP(builder.CreateZExt(inst, Int32Ty), DoubleTy);
    } else {
        return false;
    }

    Value *location = ConstantInt::get(Int32Ty, ++condCounter);
    Value *cond = inst;

    builder.CreateCall(processCondFunc, {
        location,
        cond,
        distance,
        ConstantInt::get(Int1Ty, xor_like_branching_function ? 1 : 0),
        ConstantInt::get(Int8Ty, predicate)
        });

    return true;
}

void llvm_instrumenter::instrumentCondBr(BranchInst *brInst) {
    IRBuilder<> builder(brInst);
    
    Value *location = ConstantInt::get(Int32Ty, basicBlockCounter);
    Value *cond = brInst->getCondition();

    builder.CreateCall(processCondBrFunc, {location, cond});
}

void llvm_instrumenter::replaceCalls(
    Function &F,
    std::unordered_map<std::string, FunctionCallee> replacements
    ) {
    TMPROF_BLOCK();

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
    TMPROF_BLOCK();

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

bool llvm_instrumenter::runOnFunction(Function &F, bool const br_too) {
    TMPROF_BLOCK();

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

        basic_block_dbg_info& bbDbgInfo = basicBlockDbgInfo[&BB];
        bbDbgInfo.id = basicBlockCounter;

        unsigned int dbgShift = 0U;

        bool  xor_instr_detected = false;
        for (Instruction &I: BB) {
            if (bbDbgInfo.info == nullptr) {
                bbDbgInfo.info = I.getDebugLoc();
                if (bbDbgInfo.info != nullptr)
                    bbDbgInfo.depth = 0;
            }
            ++dbgShift;

            BinaryOperator const* const binary_operator = dyn_cast<BinaryOperator>(&I);
            if (binary_operator != nullptr && binary_operator->getOpcode() == BinaryOperator::Xor) {
                xor_instr_detected = true;
            }

            if (I.getType() == Int1Ty) {
                if (instrumentCond(&I, xor_instr_detected))
                    condInstrDbgInfo.push_back({ &I, condCounter, dbgShift });
            }
        }

        BranchInst *brInst = dyn_cast<BranchInst>(BB.getTerminator());
        if (!brInst || !brInst->isConditional() || !br_too) {
            continue;
        }
        instrumentCondBr(brInst);
        brInstrDbgInfo.push_back({ brInst, basicBlockCounter, (unsigned int)BB.size() });
    }
    return true;
}


void llvm_instrumenter::propagateMissingBasicBlockDbgInfo()
{
    TMPROF_BLOCK();

    struct local
    {
        using key_type = std::pair<llvm::DILocation const*, int>;

        static bool less_than(key_type const& key0, key_type const& key1)
        {
            if (key0.first != nullptr && key1.first == nullptr)
                return true;
            if (key0.first == nullptr)
                return false;

            if (key0.second < key1.second)
                return true;
            if (key0.second != key1.second)
                return false;

            if (key0.first->getLine() < key1.first->getLine())
                return true;
            if (key0.first->getLine() != key1.first->getLine())
                return false;

            if (key0.first->getColumn() < key1.first->getColumn())
                return true;
            return false;
        }

        static void compute_basic_block_dbg_info(
            llvm::BasicBlock const* const bb,
            llvm_instrumenter::basic_block_dbg_info_map& bbInfo,
            std::unordered_set<llvm::BasicBlock const*>& visited
            )
        {
            llvm_instrumenter::basic_block_dbg_info& info = bbInfo.at(bb); 
            if (info.depth != basic_block_dbg_info::invalid_depth)
                return;

            if (visited.contains(bb))
            {
                info.depth = 0;
                return;
            }

            visited.insert(bb);

            llvm::BranchInst const* const brInstr = llvm::dyn_cast<llvm::BranchInst>(bb->getTerminator());
            if (brInstr == nullptr)
            {
                info.depth = 0;
                return;
            }

            local::key_type best { info.info, info.depth };
            for (unsigned int i = 0; i < brInstr->getNumSuccessors(); ++i) {
                compute_basic_block_dbg_info(brInstr->getSuccessor(i), bbInfo, visited);
                llvm_instrumenter::basic_block_dbg_info& succ_info = bbInfo.at(brInstr->getSuccessor(i)); 
                local::key_type const succ_key{ succ_info.info, succ_info.depth + 1 };
                if (local::less_than(succ_key, best))
                    best = succ_key;
            }

            info.info = best.first;
            info.depth = best.second;
        }
    };

    std::unordered_set<llvm::BasicBlock const*> visited{};

    for (auto const&  info : condInstrDbgInfo)
        if (info.instruction->getDebugLoc().get() == nullptr)
            local::compute_basic_block_dbg_info(info.instruction->getParent(), basicBlockDbgInfo, visited);
    for (auto const&  info : brInstrDbgInfo)
        if (info.instruction->getDebugLoc().get() == nullptr)
            local::compute_basic_block_dbg_info(info.instruction->getParent(), basicBlockDbgInfo, visited);
}

