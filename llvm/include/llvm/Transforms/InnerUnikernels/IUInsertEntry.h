#ifndef LLVM_TRANSFORMS_IUINSERTENTRY_H
#define LLVM_TRANSFORMS_IUINSERTENTRY_H

#include "llvm/ADT/StringSet.h"
#include "llvm/IR/PassManager.h"

namespace llvm {

class Module;

/// Pass to insert entry points for inner0unikernel programs
class IUEntryInsertion : public PassInfoMixin<IUEntryInsertion> {
  StringSet<> Sections = {
    "tracepoint",
  };

  bool runOnModule(Module &M);
  void insertEntry(LLVMContext &, Module &, FunctionCallee &, GlobalVariable *,
                   Type *, StringRef);
  void setIUFnAttr(LLVMContext &, Function *);

public:
  /// Perform insertion on the Main module
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);

};

} // namespace llvm

#endif /* LLVM_TRANSFORMS_IUINSERTENTRY_H */
