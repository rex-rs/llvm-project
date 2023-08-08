//===- IUInsertEntry.h - IUEntryInsertion pass ------------------*- C++ -*-===//
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
/// pass for the Inner-Unikernels project. This pass is suitable for use in
/// the new pass manager and it does not support the legacy pass manager.
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_IUINSERTENTRY_H
#define LLVM_TRANSFORMS_IUINSERTENTRY_H

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/PassManager.h"

#include <string>

namespace llvm {

/// Pass to insert entry points for inner-unikernel programs
class IUEntryInsertion : public PassInfoMixin<IUEntryInsertion> {
  static SmallVector<std::string, 16> Sections;

  bool runOnModule(Module &);
  Function *insertEntry(Module &, FunctionCallee &, GlobalVariable *, Type *,
                        StringRef, unsigned);
  AttributeList getIUFnAttr(LLVMContext &);
  void markUsedGlobalVariables(Module &, ArrayRef<Constant *>);

  inline bool isValidSection(StringRef ProgSec);

public:
  PreservedAnalyses run(Module &, ModuleAnalysisManager &);
};

} // namespace llvm

#endif /* LLVM_TRANSFORMS_IUINSERTENTRY_H */
