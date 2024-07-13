//===- RexInsertEntry.cpp - code to perform entry insertion for Rex programs-===//
//
// Part of the Inner-Unikernels project, based on the LLVM project under
// the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// This file implements the entry code insertion pass for Inner-Unikernels
// programs. It generates a new function that calls into the __rex_entry_*()
// functions in the kernel runtime crate for each global Rex program
// objects. The pass then sets the entry functions as "used" to prevent
// link-time stripping using @llvm.used, which will automatically set the
// "SHF_GNU_RETAIN" flag for these symbols.
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Rex/RexInsertEntry.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SCCIterator.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Analysis/CallGraphSCCPass.h"
#include "llvm/Demangle/Demangle.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <sstream>
#include <string>

#include <linux/bpf.h>

using namespace llvm;

#define DEBUG_TYPE "rex-entry-insertion"

STATISTIC(NumInserted, "Number of entry function inserted");

/// Validate program sections, the put the function and program object
/// into appropriate sections
void RexEntryInsertion::validateAndFinalizeSection(Function *EntryFn,
                                                  GlobalVariable *ProgObj,
                                                  unsigned ProgType) const {
  // We want to strip the "inner_unikernel/" prefix
  // strlen("rex/") = 4
  EntryFn->setSection(ProgObj->getSection().substr(4));
  switch (ProgType) {
#define REX_PROG_TYPE_1(ty_enum, ty_name, sec)                                 \
  case ty_enum:                                                                \
    ProgObj->setSection("obj" #ty_name);                                       \
    assert(EntryFn->getSection().starts_with(sec) && "invalid section name");  \
    break;
#define REX_PROG_TYPE_2(ty_enum, ty_name, sec1, sec2)                          \
  case ty_enum:                                                                \
    ProgObj->setSection("obj" #ty_name);                                       \
    assert((EntryFn->getSection().starts_with(sec1) ||                         \
            EntryFn->getSection().starts_with(sec2)) &&                        \
           "invalid section name");                                            \
    break;
#include "llvm/Transforms/Rex/RexProgType.def"
#undef REX_PROG_TYPE_1
#undef REX_PROG_TYPE_2
  default:
    llvm_unreachable("Unknown prog type");
  }
}

/// Performs the actual insertion of the new function
Function *RexEntryInsertion::insertEntry(Module &M, FunctionCallee &ProgRun,
                                        GlobalVariable *ProgObj, Type *CtxPT,
                                        StringRef Name,
                                        unsigned ProgType) const {
  LLVMContext &C = M.getContext();

  // Argument and return type
  IntegerType *EntryRetty = Type::getInt32Ty(C);
  Type *EntryArgTys[1] = {CtxPT};

  // Declare the function in module
  FunctionType *EntryTy = FunctionType::get(EntryRetty, EntryArgTys, false);
  FunctionCallee Entry = M.getOrInsertFunction(Name, EntryTy, getRexFnAttr(C));

  // Setup attributes
  Function *EntryFn = cast<Function>(Entry.getCallee());

  // Construct function body, starting with entry BB
  BasicBlock *EntryBB = BasicBlock::Create(C, "start", EntryFn);
  IRBuilder<> InstBuilder(EntryBB);

  // Bitcast away the packed attribute
  Type *SelfType = ProgRun.getFunctionType()->getParamType(0);
  Value *SelfObj = InstBuilder.CreateBitCast(ProgObj, SelfType);

  // Construct call to prog_run
  Value *ProgRunArgs[2] = {SelfObj, EntryFn->getArg(0)};
  CallInst *ProgRunCI = InstBuilder.CreateCall(
      ProgRun.getFunctionType(), ProgRun.getCallee(), ProgRunArgs);

  // Return
  InstBuilder.CreateRet(ProgRunCI);

  validateAndFinalizeSection(EntryFn, ProgObj, ProgType);

  NumInserted++;

  return EntryFn;
}

/// Sets all the needed attribute for the Rust Rex programs
AttributeList RexEntryInsertion::getRexFnAttr(LLVMContext &C) const {

  // SIMD extensions are not allowed in the kernel
  std::stringstream TargetFeatureSs;
  TargetFeatureSs << "-avx," << "-avx2," << "-sse," << "-sse2," << "-sse3,"
                  << "-sse4.1," << "-sse4.2," << "-crc32," << "-sse4a,"
                  << "-ssse3," << "-avx," << "-avx2," << "-sse," << "-sse2,"
                  << "-sse3," << "-sse4.1," << "-sse4.2," << "-crc32,"
                  << "-sse4a," << "-ssse3";

  // Other needed attributes, e.g. kernel does not have redzone
  AttributeList AS;
  AS = AS.addFnAttribute(C, Attribute::AttrKind::NoRedZone)
           .addFnAttribute(C, Attribute::AttrKind::NoUnwind)
           .addFnAttribute(C, Attribute::AttrKind::NonLazyBind)
           .addFnAttribute(C, "probe-stack", "__rust_probestack")
           .addFnAttribute(C, "target-cpu", "x86-64")
           .addFnAttribute(C, "target-features", TargetFeatureSs.str())
           .addFnAttribute(C, "tune-cpu", "generic");
  return AS;
}

/// Entry point of the pass, it looks at all the global variables to identify
/// the inner-unikernel program variables
bool RexEntryInsertion::runOnModule(Module &M) const {
  bool Changed = false; // Whether transformation is actually made
  LLVMContext &C = M.getContext();
  SmallVector<GlobalValue *, 8> UsedGV;

  // Perform stack depth instrumentation
  Changed |= instrumentStack(M, C);

  NamedMDNode *NamedMD = M.getOrInsertNamedMetadata("rex-programs");

  LLVMContext &Context = M.getContext();

  // Traverse all Global variables
  for (GlobalVariable &G : M.globals()) {
    if (G.hasSection() && G.getSection().starts_with("rex")) {
      Constant *Init = G.getInitializer();
      auto *CS = cast<ConstantStruct>(Init);

      // rtti
      // Run-Time Type Information (RTTI) is a feature in C++ that allows the
      // type of an object to be determined during program execution
      Constant *OP0 = CS->getOperand(0);
      auto *OP0Cda = cast<ConstantDataArray>(OP0);
      const char *RawRTTI = OP0Cda->getRawDataValues().data();
      auto RTTI = *reinterpret_cast<const int *>(RawRTTI);

      std::string ProgRunName;
      switch (RTTI) {
#define REX_PROG_TYPE_1(ty_enum, ty_name, sec)                                 \
  case ty_enum:                                                                \
    ProgRunName = "__rex_entry_" #ty_name;                                     \
    break;
#define REX_PROG_TYPE_2(ty_enum, ty_name, sec1, sec2)                          \
  case ty_enum:                                                                \
    ProgRunName = "__rex_entry_" #ty_name;                                     \
    break;
#include "llvm/Transforms/Rex/RexProgType.def"
#undef REX_PROG_TYPE_1
#undef REX_PROG_TYPE_2
      default:
        errs() << "Unknown RTTI " << RTTI << "\n";
      }

      // prog_fn
      Constant *OP1 = CS->getOperand(1);
      Function *Func = cast<Function>(OP1);
      FunctionType *FuncType = Func->getFunctionType();

      Type *ProgSelfTy = FuncType->getParamType(0);

      SmallVector<Type *, 0> CtxTys;
      PointerType *CtxPT = StructType::get(C, CtxTys)->getPointerTo();

      Type *ProgRunArgTys[2] = {ProgSelfTy, CtxPT};
      IntegerType *ProgRunRetty = Type::getInt32Ty(C);

      FunctionType *ProgRunTy =
          FunctionType::get(ProgRunRetty, ProgRunArgTys, false);
      FunctionCallee ProgRun =
          M.getOrInsertFunction(ProgRunName, ProgRunTy, getRexFnAttr(C));

      // name: &'a str
      Constant *OP2 = CS->getOperand(2);

      Constant *ProgNameInit = cast<GlobalVariable>(OP2)->getInitializer();
      auto *ProgNameStruct = cast<ConstantStruct>(ProgNameInit);
      auto *ProgNameCda =
          cast<ConstantDataArray>(ProgNameStruct->getOperand(0));
      std::string ProgName(ProgNameCda->getRawDataValues().data(),
                           ProgNameCda->getType()->getNumElements());

      // Add inserted program name metadata to backend pass
      StringRef UserProg = Func->getName();
      Metadata *Str = MDString::get(Context, UserProg);
      MDNode *Node = MDNode::get(Context, Str);
      NamedMD->addOperand(Node);

      // Add the function using the extracted information above
      Function *EntryFunc = insertEntry(M, ProgRun, &G, CtxPT, ProgName, RTTI);
      UsedGV.push_back(EntryFunc);

      // Transformation made
      Changed = true;
    }
  }

  // Make sure the timeout handler is always in the final executable
  UsedGV.push_back(createTimeoutHandler(M, C));

  // Mark the Variables (i.e. inserted functions and rex-prog objects) as
  // used as these symbols are typically considered as dead code during the
  // linking stage if the '--gc-sections' option is supplied to the linker.
  // Marking the symbols as used would add the 'SHF_GNU_RETAIN' flag and
  // prevent the linker from stripping them away.
  // See also TargetLoweringObjectFileELF::getExplicitSectionGlobal and
  // collectUsedGlobalVariables
  if (Changed)
    appendToUsed(M, UsedGV);

  return Changed;
}

bool RexEntryInsertion::instrumentStack(Module &M, LLVMContext &C) const {
  SmallVector<Instruction *, 32> WorkList;
  bool HasIndirect = false;

  // Find all calls to other functions
  for (auto &F : M) {
    std::string Demangled;
    nonMicrosoftDemangle(F.getName().data(), Demangled);
    if (StringRef(Demangled).starts_with(StringRef("rex::")))
      continue;
    for (auto &I : instructions(F)) {
      if (auto *CI = dyn_cast<CallBase>(&I)) {
        Value *V = CI->getCalledOperand();
        // Ignore inline asm and intrinsics
        if (isa<InlineAsm>(V))
          continue;
        if (auto *F = dyn_cast<Function>(V)) {
          if (F->isIntrinsic())
            continue;
        }

        HasIndirect |= CI->isIndirectCall();
        WorkList.push_back(CI);
      }
    }
  }

  // No need to instrument if there is no call function
  if (WorkList.empty())
    return false;

  // No need to instrument if there is no indirect call and no recursion
  // will calculate the frame size in backend pass RexFrameSizePass
  if (!HasIndirect && !Recursive)
    return false;

  // Add metadata to backend pass
  if (HasIndirect) {
    NamedMDNode *NamedMD = M.getOrInsertNamedMetadata("rex-stack");
    LLVMContext &Context = M.getContext();
    Metadata *Str = MDString::get(Context, "rex-indirect-call");
    MDNode *Node = MDNode::get(Context, Str);
    NamedMD->addOperand(Node);
  }

  FunctionType *CheckStackTy = FunctionType::get(Type::getVoidTy(C), {}, false);
  FunctionCallee CheckStack =
      M.getOrInsertFunction("__rex_check_stack", CheckStackTy, getRexFnAttr(C));

  // Add the stack pointer instrumentation
  for (auto *I : WorkList) {
    IRBuilder<> InstBuilder(I);
    InstBuilder.CreateCall(CheckStack);
  }

  return true;
}

Function *RexEntryInsertion::createTimeoutHandler(Module &M,
                                                 LLVMContext &C) const {
  // Rust uses void return type for noreturn (i.e. the "!" return type)
  FunctionType *TimeoutHandlerTy =
      FunctionType::get(Type::getVoidTy(C), {}, false);
  FunctionCallee TimeoutHandlerInner = M.getOrInsertFunction(
      "__rex_handle_timeout", TimeoutHandlerTy, getRexFnAttr(C));

  Function *TimeoutHandler = cast<Function>(
      M.getOrInsertFunction(M.getName().str() + "_rex_handle_timeout",
                            TimeoutHandlerTy, getRexFnAttr(C))
          .getCallee());

  // Construct function body, starting with entry BB
  BasicBlock *EntryBB = BasicBlock::Create(C, "start", TimeoutHandler);
  IRBuilder<> InstBuilder(EntryBB);

  // Construct call to __rex_handle_timeout
  InstBuilder.CreateCall(TimeoutHandlerInner.getFunctionType(),
                         TimeoutHandlerInner.getCallee(), {});

  InstBuilder.CreateRetVoid();

  return TimeoutHandler;
}

/// Wrapper for the new pass manager
PreservedAnalyses RexEntryInsertion::run(Module &M, ModuleAnalysisManager &AM) {
  // Run entry insertion pass
  Recursive = false;
  CallGraph &CG = AM.getResult<CallGraphAnalysis>(M);

  // Check whether we have a loop somewhere
  for (scc_iterator<CallGraph *> SCCI = scc_begin(&CG); !SCCI.isAtEnd();
       ++SCCI) {
    if (SCCI.hasCycle()) {
      Recursive = true;
      break;
    }
  }

  if (Recursive) {
    errs() << "Found recursive call graph with Module " << M.getName() << "\n";
    NamedMDNode *NamedMD = M.getOrInsertNamedMetadata("rex-stack");
    LLVMContext &Context = M.getContext();
    Metadata *Str = MDString::get(Context, "rex-recursion");
    MDNode *Node = MDNode::get(Context, Str);
    NamedMD->addOperand(Node);
  }

  bool Changed = runOnModule(M);

  // Invalidate all analysis if any new code has been added
  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
