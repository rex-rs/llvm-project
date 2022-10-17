#include "llvm/ADT/Statistic.h"
#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include <string>

using namespace llvm;

#define DEBUG_TYPE "iu-entry-insertion"

STATISTIC(NumInserted,  "Number of entry function inserted");

namespace { // Begin Anonymous namespace

  class IUEntryInsertion : public ModulePass {
  public:
    static char ID;
    static StringMap<std::string> MangledNameMap;

    IUEntryInsertion() : ModulePass(ID) {}
    bool runOnModule(Module &) override;
    void getAnalysisUsage(AnalysisUsage &) const override;
  };

} // End Anonymous namespace

char IUEntryInsertion::ID = 0;

// Registration
static RegisterPass<IUEntryInsertion> X("iu-entry-insertion",
        "Insert inner-unikernel entry function",
        false,
        false);

void IUEntryInsertion::getAnalysisUsage(AnalysisUsage &AU) const {
  // Does it alter CFG?
  // The pass will certainly add more functions to the Module...
}

bool IUEntryInsertion::runOnModule(Module &M) {
  return false;
}
