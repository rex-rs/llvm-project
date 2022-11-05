#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/InnerUnikernels/IUInsertEntry.h"

#include <sstream>
#include <string>

extern "C" {

#include <linux/bpf.h>

}

using namespace llvm;

#define DEBUG_TYPE "iu-entry-insertion"

STATISTIC(NumInserted,  "Number of entry function inserted");

/// Performs the actual insertion of the new function
void IUEntryInsertion::insertEntry(LLVMContext &C, Module &M,
  FunctionCallee &ProgRun, GlobalVariable *ProgObj, Type *CtxPT,
  StringRef EntryName, unsigned ProgType) {

  // Argument and return type
  auto *EntryRetty = Type::getInt32Ty(C);
  Type *EntryArgTys[1] = { CtxPT };

  // Declare the function in module
  auto *EntryTy = FunctionType::get(EntryRetty, EntryArgTys, false);
  auto Entry = M.getOrInsertFunction(EntryName, EntryTy);

  // Setup attributes
  auto *EntryFn = cast<Function>(Entry.getCallee());
  setIUFnAttr(C, EntryFn);

  // Construct function body, starting with entry BB
  auto *EntryBB = BasicBlock::Create(C, "start", EntryFn);\
  IRBuilder<> InstBuilder(EntryBB);

  // Bitcast away the packed attribute
  auto *SelfType = ProgRun.getFunctionType()->getParamType(0);
  auto *SelfObj = InstBuilder.CreateBitCast(ProgObj, SelfType);

  // Construct call to prog_run
  Value *ProgRunArgs[2] = { SelfObj, EntryFn->getArg(0) };
  auto *ProgRunCI = InstBuilder.CreateCall(ProgRun.getFunctionType(),
                                           ProgRun.getCallee(),
                                           ProgRunArgs);

  // Return
  InstBuilder.CreateRet(ProgRunCI);

  // Put the function into the appropriate section
  switch (ProgType) {
  case BPF_PROG_TYPE_TRACEPOINT:
    EntryFn->setSection("tracepoint");
    break;
  default:
    llvm_unreachable("unknown prog type");
  }

  NumInserted++;
}

/// Sets all the needed attribute for the Rust IU programs
void IUEntryInsertion::setIUFnAttr(LLVMContext &C, Function *F) {

  // SIMD extensions are not allowed in the kernel
  std::stringstream TargetFeatureSs;
  TargetFeatureSs << "-avx," << "-avx2," << "-sse," << "-sse2," << "-sse3,"
                  << "-sse4.1," << "-sse4.2," << "-crc32," << "-sse4a,"
                  << "-ssse3," << "-avx," << "-avx2," << "-sse," << "-sse2,"
                  << "-sse3," << "-sse4.1," << "-sse4.2," << "-crc32,"
                  << "-sse4a," << "-ssse3";

  // Other needed attributes, e.g. kernel does not have redzone
  auto AS = F->getAttributes();
  AS = AS.addFnAttribute(C, Attribute::AttrKind::NoRedZone)
         .addFnAttribute(C, Attribute::AttrKind::NoUnwind)
         .addFnAttribute(C, Attribute::AttrKind::NonLazyBind)
         .addFnAttribute(C, "probe-stack", "__rust_probestack")
         .addFnAttribute(C, "target-cpu", "x86-64")
         .addFnAttribute(C, "target-features", TargetFeatureSs.str())
         .addFnAttribute(C, "tune-cpu", "generic");
  F->setAttributes(AS);
}

/// Entry point of the pass, it looks at all the global variables to identify
/// the inner-unikernel program variables
bool IUEntryInsertion::runOnModule(Module &M) {
  bool Changed = false; // Whether transformation is actually made
  auto &C = M.getContext();

  // Traverse all Global variables
  for (auto &G: M.globals()) {
    if (G.hasSection() && Sections.contains(G.getSection())) {
      auto *Init = G.getInitializer();
      auto *CS = cast<ConstantStruct>(Init);

      // rtti
      auto *OP0 = CS->getOperand(0);
      auto *CDA = cast<ConstantDataArray>(OP0);
      const auto *RawRTTI = CDA->getRawDataValues().data();
      auto RTTI = *reinterpret_cast<const int *>(RawRTTI);

      std::string ProgRunName;
      switch (RTTI) {
      case BPF_PROG_TYPE_TRACEPOINT:
        ProgRunName = "__iu_entry_tracepoint";
        break;
      default:
        llvm_unreachable("Unknown program type");
      }

      // prog_fn
      auto *OP1 = CS->getOperand(1);
      auto *OP1CE = cast<ConstantExpr>(OP1);

      auto *ST = OP1CE->getOperand(0)->getType();
      auto *PointeeT = cast<PointerType>(ST)->getNonOpaquePointerElementType();

      auto *FT = cast<FunctionType>(PointeeT);
      auto *SelfT = FT->getParamType(0);

      SmallVector<Type *, 0> CtxTTys;
      auto *CtxPT = StructType::create(C, CtxTTys)->getPointerTo();

      Type *ProgRunArgTys[2] = { SelfT, CtxPT };
      auto *ProgRunRetty = Type::getInt32Ty(C);

      auto *ProgRunTy = FunctionType::get(ProgRunRetty, ProgRunArgTys, false);

      auto ProgRun = M.getOrInsertFunction(ProgRunName, ProgRunTy);
      auto *ProgRunFn = cast<Function>(ProgRun.getCallee());

      setIUFnAttr(C, ProgRunFn);

      // name: &'a str
      auto *OP2 = CS->getOperand(2);
      auto *OP2CE = cast<ConstantExpr>(OP2);

      auto *ProgNameInit = cast<GlobalVariable>(OP2CE->getOperand(0))->getInitializer();
      auto *ProgNameStruct = cast<ConstantStruct>(ProgNameInit);
      auto *ProgNameCda = cast<ConstantDataArray>(ProgNameStruct->getOperand(0));
      std::string ProgName(ProgNameCda->getRawDataValues().data(),
                           ProgNameCda->getType()->getNumElements());

      // Add the function using the extracted information above
      insertEntry(C, M, ProgRun, &G, CtxPT, ProgName, RTTI);

      // Transformation made
      Changed = true;
    }
  }

  return Changed;
}

/// Wrapper for the new pass manager
PreservedAnalyses IUEntryInsertion::run(Module &M,
                                        ModuleAnalysisManager &AM) {
  // Run entry insertion pass
  runOnModule(M);

  // Invalidate all analysis given that new code has been added
  return PreservedAnalyses::none();
}
