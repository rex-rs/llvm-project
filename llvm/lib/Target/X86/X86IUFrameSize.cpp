#include "X86.h"
#include "X86Subtarget.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/Demangle/Demangle.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"

#include <cstdint>
#include <stack>

using namespace llvm;

#define X86IUFrameSizePassName "X86 frame buffer size check"
#define PASS_KEY "x86-frame-buffer-size"
#define DEBUG_TYPE PASS_KEY

namespace {

class X86IUFrameSizePassMF {
public:
  X86IUFrameSizePassMF(const Module *M, const MachineModuleInfo *MMI)
      : M(M), MMI(MMI) {}
  bool run();
  void runOnMachineFunction(MachineFunction &MF);

private:
  const Module *M;
  const MachineModuleInfo *MMI;
  uint64_t getFrameSize(const MachineFunction &MF);

  /// We can give the program 1 extra page nominally when the total stack depth
  /// can be statically calculated
  static constexpr uint64_t FrameSizeLimit = (0x1000UL << 2) - 0x1000;
};

class X86IUFrameSizePass : public ModulePass {
public:
  static char ID;

  X86IUFrameSizePass() : ModulePass(ID) {}
  bool runOnModule(Module &M) override;
  StringRef getPassName() const override { return X86IUFrameSizePassName; }
  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<MachineModuleInfoWrapperPass>();
    AU.setPreservesAll();
    ModulePass::getAnalysisUsage(AU);
  }
};

} // end anonymous namespace

char X86IUFrameSizePass::ID = 0;

INITIALIZE_PASS(X86IUFrameSizePass, PASS_KEY, X86IUFrameSizePassName, false,
                true)

ModulePass *llvm::createX86IUFrameSizePass() {
  return new X86IUFrameSizePass();
}

bool X86IUFrameSizePass::runOnModule(Module &M) {
  const MachineModuleInfo *MMI =
      &getAnalysis<MachineModuleInfoWrapperPass>().getMMI();
  return X86IUFrameSizePassMF(&M, MMI).run();
}

bool X86IUFrameSizePassMF::run() {

  bool Failed = false;

  // check for iu-stack iu-indirect-call and recursion
  NamedMDNode *IUStackMD = M->getNamedMetadata("iu-stack");

  if (IUStackMD) {
    for (unsigned I = 0, E = IUStackMD->getNumOperands(); I != E; ++I) {
      MDNode *Node = IUStackMD->getOperand(I);
      if (MDString *Str = dyn_cast<MDString>(Node->getOperand(0))) {
        StringRef Value = Str->getString();

        // skip pass with recursion
        if (Value == "iu-recursion")
          Failed |= true;

        if (Value == "iu-indirect-call")
          Failed |= true;
      }
    }

    if (Failed)
      return false;
  }

  SmallVector<StringRef, 32> WorkList;

  // get the iu-program function name
  NamedMDNode *IUProgMD = M->getNamedMetadata("iu-programs");

  if (IUProgMD) {
    for (unsigned I = 0, E = IUProgMD->getNumOperands(); I != E; ++I) {
      MDNode *Node = IUProgMD->getOperand(I);
      if (MDString *Str = dyn_cast<MDString>(Node->getOperand(0))) {

        // add entry function to the worklist
        StringRef Value = Str->getString();
        WorkList.push_back(Value);
      }
    }
  }

  if (WorkList.empty())
    return false;

  // Lambda function to check if a string is in a vector
  auto FoundInVec = [&](const SmallVector<StringRef, 32> &Vec,
                        const StringRef &Target) {
    return std::any_of(Vec.begin(), Vec.end(), [&Target](const StringRef &Str) {
      return Str.equals(Target);
    });
  };

  for (auto &F : *M) {
    if (F.empty())
      continue;

    MachineFunction *MF = MMI->getMachineFunction(F);
    if (!MF)
      continue;

    if (!FoundInVec(WorkList, F.getName()))
      continue;

    runOnMachineFunction(*MF);
  }
  return false;
}

void X86IUFrameSizePassMF::runOnMachineFunction(MachineFunction &MF) {
  uint64_t FrameSize = getFrameSize(MF);
  if (FrameSize > FrameSizeLimit) {
    std::string ErrMsg;
    raw_string_ostream OS(ErrMsg);
    std::string Demangled;

    nonMicrosoftDemangle(MF.getName().data(), Demangled);
    OS << "Frame size is too large: " << FrameSize
       << " with function: " << Demangled << "\n";
    report_fatal_error(StringRef(ErrMsg));
  }
}

uint64_t X86IUFrameSizePassMF::getFrameSize(const MachineFunction &MF) {

  using FrameSizeEntry = std::pair<const MachineFunction *, uint64_t>;

  std::stack<FrameSizeEntry, SmallVector<FrameSizeEntry, 32>> WorkList;

  WorkList.push({&MF, MF.getFrameInfo().getStackSize()});

  uint64_t MaxFrameSize = 0;

  while (!WorkList.empty()) {
    FrameSizeEntry CurrentEntry = WorkList.top();
    WorkList.pop();

    const MachineFunction *CurrentMF = CurrentEntry.first;
    uint64_t AccumulatedSize = CurrentEntry.second;

    uint64_t CurrFrameSize = CurrentMF->getFrameInfo().getStackSize();
    AccumulatedSize += CurrFrameSize;
    MaxFrameSize = std::max(MaxFrameSize, AccumulatedSize);

    // skip if the stack size is too large
    if (MaxFrameSize > FrameSizeLimit)
      return MaxFrameSize;

    for (auto &MBB : *CurrentMF) {
      for (auto &MI : MBB) {
        if (MI.isCall()) {
          // Handle the call instruction
          for (auto &MO : MI.operands()) {
            if (!MO.isGlobal())
              continue;

            if (const Function *CalledFunction =
                    dyn_cast<Function>(MO.getGlobal())) {
              MachineFunction *MFCalled =
                  MMI->getMachineFunction(*CalledFunction);

              // skip if the function is nullptr
              if (!MFCalled) {
                continue;
              }

              std::string Demangled;
              nonMicrosoftDemangle(CalledFunction->getName().data(), Demangled);
              // skip if the function is a core function
              if (StringRef(Demangled).startswith(StringRef("<core::")) ||
                  StringRef(Demangled).startswith(StringRef("core::"))) {
                AccumulatedSize += 24;
                continue;
              }

              WorkList.push({MFCalled, AccumulatedSize});
            }
          }
        }
      }
    }
  }
  return MaxFrameSize;
}