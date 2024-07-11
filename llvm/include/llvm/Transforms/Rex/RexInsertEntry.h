//===- RexInsertEntry.h - RexEntryInsertion pass ----------------*- C++ -*-===//
//
// Part of the Inner-Unikernels project, based on the LLVM project under
// the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
/// \file
///
/// This file provides the primary interface to the entry-code-insertion
/// pass for the Rex project. This pass is suitable for use in the new pass
/// managermanager and it does not support the legacy pass manager.
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_REXINSERTENTRY_H
#define LLVM_TRANSFORMS_REXINSERTENTRY_H

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/PassManager.h"

namespace llvm {

/// Pass to insert entry points for inner-unikernel programs
class RexEntryInsertion : public PassInfoMixin<RexEntryInsertion> {
  bool runOnModule(Module &M) const;
  Function *insertEntry(Module &M, FunctionCallee &ProgRun,
                        GlobalVariable *ProgObj, Type *CtxPT, StringRef Name,
                        unsigned ProgType) const;
  AttributeList getRexFnAttr(LLVMContext &C) const;
  void markUsedGlobalVariables(Module &M, ArrayRef<Constant *> Vec) const;
  void validateAndFinalizeSection(Function *EntryFn, GlobalVariable *ProgObj,
                                  unsigned ProgType) const;
  bool instrumentStack(Module &M, LLVMContext &C) const;
  Function *createTimeoutHandler(Module &M, LLVMContext &C) const;

  bool Recursive;

public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
};

} // namespace llvm

#endif /* LLVM_TRANSFORMS_REXINSERTENTRY_H */
