#ifndef LLVM_TRANSFORMS_IUINSERTENTRY_H
#define LLVM_TRANSFORMS_IUINSERTENTRY_H

#include "llvm/ADT/StringSet.h"
#include "llvm/IR/PassManager.h"

namespace llvm {

/// Pass to insert entry points for inner-unikernel programs
class IUEntryInsertion : public PassInfoMixin<IUEntryInsertion> {
  StringSet<> Sections = {
    "iu_tracepoint",
  };

  bool runOnModule(Module &);
  void insertEntry(LLVMContext &, Module &, FunctionCallee &, GlobalVariable *,
                   Type *, StringRef, unsigned);
  void setIUFnAttr(LLVMContext &, Function *);

public:
  PreservedAnalyses run(Module &, ModuleAnalysisManager &);

};

} // namespace llvm

#endif /* LLVM_TRANSFORMS_IUINSERTENTRY_H */
