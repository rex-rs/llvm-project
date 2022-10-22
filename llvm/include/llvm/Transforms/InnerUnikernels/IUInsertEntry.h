#ifndef LLVM_TRANSFORMS_IUINSERTENTRY_H
#define LLVM_TRANSFORMS_IUINSERTENTRY_H

#include "llvm/IR/PassManager.h"

namespace llvm {

class Module;

/// Pass to insert entry points for inner0unikernel programs
class IUEntryInsertion : public PassInfoMixin<IUEntryInsertion> {
public:
	/// Perform insertion on the Main module
	PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
};

}

#endif /* LLVM_TRANSFORMS_IUINSERTENTRY_H */
