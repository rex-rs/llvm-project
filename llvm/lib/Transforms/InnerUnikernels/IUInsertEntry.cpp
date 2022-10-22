#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/InnerUnikernels/IUInsertEntry.h"
#include <string>

using namespace llvm;

#define DEBUG_TYPE "iu-entry-insertion"

STATISTIC(NumInserted,  "Number of entry function inserted");

PreservedAnalyses IUEntryInsertion::run(Module &M,
                                        ModuleAnalysisManager &AM) {
  // Invalidate all analysis
  return PreservedAnalyses::none();
}
