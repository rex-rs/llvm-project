//===- IUInsertEntry.cpp - code to perform entry insertion for IU programs-===//
//
// Part of the Inner-Unikernels project, based on the LLVM project under
// the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// This file implements the entry code insertion pass for Inner-Unikernels
// programs. It generates a new function that calls into the __iu_entry_*()
// functions in the kernel runtime crate for each global IU program
// objects. The pass then sets the entry functions as "used" to prevent
// link-time stripping using @llvm.used, which will automatically set the
// "SHF_GNU_RETAIN" flag for these symbols.
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/InnerUnikernels/IUInsertEntry.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/GlobalValue.h"
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

#include <sstream>
#include <string>

extern "C" {
#include <linux/bpf.h>
}

using namespace llvm;

#define DEBUG_TYPE "iu-entry-insertion"

STATISTIC(NumInserted, "Number of entry function inserted");

SmallVector<std::string, 16> IUEntryInsertion::Sections = {
    "tracepoint",
};

/// Performs the actual insertion of the new function
Function *IUEntryInsertion::insertEntry(Module &M, FunctionCallee &ProgRun,
                                        GlobalVariable *ProgObj, Type *CtxPT,
                                        StringRef Name, unsigned ProgType) {
  auto &C = M.getContext();

  // Argument and return type
  auto *EntryRetty = Type::getInt32Ty(C);
  Type *EntryArgTys[1] = {CtxPT};

  // Declare the function in module
  auto *EntryTy = FunctionType::get(EntryRetty, EntryArgTys, false);
  auto Entry = M.getOrInsertFunction(Name, EntryTy);

  // Setup attributes
  auto *EntryFn = cast<Function>(Entry.getCallee());
  setIUFnAttr(C, EntryFn);

  // Construct function body, starting with entry BB
  auto *EntryBB = BasicBlock::Create(C, "start", EntryFn);
  IRBuilder<> InstBuilder(EntryBB);

  // Bitcast away the packed attribute
  auto *SelfType = ProgRun.getFunctionType()->getParamType(0);
  auto *SelfObj = InstBuilder.CreateBitCast(ProgObj, SelfType);

  // Construct call to prog_run
  Value *ProgRunArgs[2] = {SelfObj, EntryFn->getArg(0)};
  auto *ProgRunCI = InstBuilder.CreateCall(ProgRun.getFunctionType(),
                                           ProgRun.getCallee(), ProgRunArgs);

  // Return
  InstBuilder.CreateRet(ProgRunCI);

  // Put the function and program object into appropriate sections
  EntryFn->setSection(ProgObj->getSection());
  switch (ProgType) {
  case BPF_PROG_TYPE_TRACEPOINT: {
    ProgObj->setSection("obj_tracepoint");
    std::string SecPrefix("tracepoint");
    auto Match = EntryFn->getSection().str().compare(0, SecPrefix.size(), SecPrefix);
    assert(!Match && "invalid section name");
    break;
  }
  default:
    llvm_unreachable("unknown prog type");
  }

  NumInserted++;

  return EntryFn;
}

/// Sets all the needed attribute for the Rust IU programs
void IUEntryInsertion::setIUFnAttr(LLVMContext &C, Function *F) {

  // SIMD extensions are not allowed in the kernel
  std::stringstream TargetFeatureSs;
  TargetFeatureSs << "-avx,"
                  << "-avx2,"
                  << "-sse,"
                  << "-sse2,"
                  << "-sse3,"
                  << "-sse4.1,"
                  << "-sse4.2,"
                  << "-crc32,"
                  << "-sse4a,"
                  << "-ssse3,"
                  << "-avx,"
                  << "-avx2,"
                  << "-sse,"
                  << "-sse2,"
                  << "-sse3,"
                  << "-sse4.1,"
                  << "-sse4.2,"
                  << "-crc32,"
                  << "-sse4a,"
                  << "-ssse3";

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

/// Mark the Variables (i.e. inserted functions and iu-prog objects) as
/// used as these symbols are typically considered as dead code during the
/// linking stage if the '--gc-sections' option is supplied to the linker.
/// Marking the symbols as used would add the 'SHF_GNU_RETAIN' flag and
/// prevent the linker from stripping them away.
/// See also TargetLoweringObjectFileELF::getExplicitSectionGlobal and
/// collectUsedGlobalVariables
void IUEntryInsertion::markUsedGlobalVariables(Module &M,
                                               ArrayRef<Constant *> Vec) {
  auto &C = M.getContext();
  const char *UsedName = "llvm.used";

  // Create initializer for @llvm.used
  auto *UsedInitElemTy = Type::getInt8Ty(C)->getPointerTo();
  auto *UsedInitArrayTy = ArrayType::get(UsedInitElemTy, Vec.size());
  auto *UsedInit = ConstantArray::get(UsedInitArrayTy, Vec);

  // FIXME: Do not handle existing @llvm.used for now
  assert(!M.getNamedValue(UsedName) && "@llvm.used exists!");

  // Create @llvm.used in the module with initializer
  auto *UsedConst = M.getOrInsertGlobal(UsedName, UsedInitArrayTy, [&] {
    return new GlobalVariable(M, UsedInitArrayTy, false,
                              GlobalVariable::AppendingLinkage, UsedInit,
                              UsedName);
  });

  // Set section
  auto *UsedGV = cast<GlobalVariable>(UsedConst);
  UsedGV->setSection("llvm.metadata");
}

/// Entry point of the pass, it looks at all the global variables to identify
/// the inner-unikernel program variables
bool IUEntryInsertion::runOnModule(Module &M) {
  bool Changed = false; // Whether transformation is actually made
  auto &C = M.getContext();
  SmallVector<Constant *, 8> UsedGV;
  auto *Int8PtrTy = Type::getInt8Ty(C)->getPointerTo();

  // Traverse all Global variables
  for (auto &G : M.globals()) {
    if (G.hasSection() && isValidSection(G.getSection())) {
      auto *Init = G.getInitializer();
      auto *CS = cast<ConstantStruct>(Init);

      // rtti
      auto *OP0 = CS->getOperand(0);
      auto *OP0Cda = cast<ConstantDataArray>(OP0);
      const auto *RawRTTI = OP0Cda->getRawDataValues().data();
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

      auto *OP1SrcTy = OP1CE->getOperand(0)->getType();
      auto *OP1PointeeT = OP1SrcTy->getNonOpaquePointerElementType();

      auto *ProgFuncTy = cast<FunctionType>(OP1PointeeT);
      auto *ProgSelfTy = ProgFuncTy->getParamType(0);

      SmallVector<Type *, 0> CtxTys;
      auto *CtxPT = StructType::create(C, CtxTys)->getPointerTo();

      Type *ProgRunArgTys[2] = {ProgSelfTy, CtxPT};
      auto *ProgRunRetty = Type::getInt32Ty(C);

      auto *ProgRunTy = FunctionType::get(ProgRunRetty, ProgRunArgTys, false);

      auto ProgRun = M.getOrInsertFunction(ProgRunName, ProgRunTy);
      auto *ProgRunFn = cast<Function>(ProgRun.getCallee());

      setIUFnAttr(C, ProgRunFn);

      // name: &'a str
      auto *OP2 = CS->getOperand(2);
      auto *OP2CE = cast<ConstantExpr>(OP2);

      auto *ProgNameInit =
          cast<GlobalVariable>(OP2CE->getOperand(0))->getInitializer();
      auto *ProgNameStruct = cast<ConstantStruct>(ProgNameInit);
      auto *ProgNameCda =
          cast<ConstantDataArray>(ProgNameStruct->getOperand(0));
      std::string ProgName(ProgNameCda->getRawDataValues().data(),
                           ProgNameCda->getType()->getNumElements());

      // Add the function using the extracted information above
      auto *EntryFunc = insertEntry(M, ProgRun, &G, CtxPT, ProgName, RTTI);
      auto *EntryFuncInt8Ptr = ConstantExpr::getBitCast(EntryFunc, Int8PtrTy);
      UsedGV.push_back(EntryFuncInt8Ptr);

      // Transformation made
      Changed = true;
    }
  }

  // Mark the inserted symbols as used
  if (Changed)
    markUsedGlobalVariables(M, UsedGV);

  return Changed;
}

/// Wrapper for the new pass manager
PreservedAnalyses IUEntryInsertion::run(Module &M, ModuleAnalysisManager &AM) {
  // Run entry insertion pass
  bool Changed = runOnModule(M);

  // Invalidate all analysis if any new code has been added
  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
