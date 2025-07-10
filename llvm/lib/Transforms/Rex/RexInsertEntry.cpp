//===- RexInsertEntry.cpp - performs entry insertion for Rex programs -----===//
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
#include "llvm/ADT/SCCIterator.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Analysis/CallGraphSCCPass.h"
#include "llvm/Demangle/Demangle.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Casting.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

#define DEBUG_TYPE "rex-entry-insertion"

/// Entry point of the pass, it looks at all the global variables to identify
/// the inner-unikernel program variables
bool RexEntryInsertion::runOnModule(Module &M) const {
  bool Changed = false; // Whether transformation is actually made
  LLVMContext &C = M.getContext();
  SmallVector<GlobalValue *, 8> UsedGV;

  // Perform stack depth instrumentation
  Changed |= instrumentStack(M, C);

  NamedMDNode *NamedMD = M.getOrInsertNamedMetadata("rex-programs");

  // Process the entry functions created by proc-macro
  for (Function &F : M.functions()) {
    if (F.hasSection() && F.getSection().starts_with("rex")) {
      F.setSection(F.getSection().substr(4));

      // Add program name metadata to backend pass
      MDNode *Node = MDNode::get(C, MDString::get(C, F.getName()));
      NamedMD->addOperand(Node);

      // Add functions to llvm.used
      UsedGV.push_back(&F);
      Changed = true;
    }
  }

  // Now process the timeout handler -- we need to make sure the timeout handler
  // is always in the final executable.
  //
  // Rust uses void return type for noreturn (i.e. the "!" return type)
  // Module::getOrInsertFunction should always be able to find the actual
  // function because lto=true and codegen-unit=1 are always set for compilation
  // of Rex prgorams
  FunctionType *TimeoutHandlerTy =
      FunctionType::get(Type::getVoidTy(C), {}, false);
  FunctionCallee TimeoutHandler =
      M.getOrInsertFunction("__rex_handle_timeout", TimeoutHandlerTy);
  UsedGV.push_back(cast<GlobalValue>(TimeoutHandler.getCallee()));

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

  // Module::getOrInsertFunction should always be able to find the actual
  // function because lto=true and codegen-unit=1 are always set for compilation
  // of Rex prgorams
  FunctionType *CheckStackTy = FunctionType::get(Type::getVoidTy(C), {}, false);
  FunctionCallee CheckStack =
      M.getOrInsertFunction("__rex_check_stack", CheckStackTy);

  // Add the stack pointer instrumentation
  for (auto *I : WorkList) {
    IRBuilder<> InstBuilder(I);
    InstBuilder.CreateCall(CheckStack);
  }

  return true;
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
