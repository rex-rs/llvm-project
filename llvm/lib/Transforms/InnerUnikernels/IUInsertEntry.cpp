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
#include "llvm/ADT/GraphTraits.h"
#include "llvm/ADT/SCCIterator.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Analysis/CallGraphSCCPass.h"
#include "llvm/Demangle/Demangle.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/InstrTypes.h"
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
#include <stack>
#include <string>

#include <linux/bpf.h>

using namespace llvm;

#define DEBUG_TYPE "iu-entry-insertion"

STATISTIC(NumInserted, "Number of entry function inserted");

/// Validate program sections, the put the function and program object
/// into appropriate sections
void IUEntryInsertion::validateAndFinalizeSection(Function *EntryFn,
                                                  GlobalVariable *ProgObj,
                                                  unsigned ProgType) const {
  // We want to strip the "inner_unikernel/" prefix
  // strlen("inner_unikernel/") + 1 = 16
  EntryFn->setSection(ProgObj->getSection().substr(16));
  switch (ProgType) {
#define IU_PROG_TYPE_1(ty_enum, ty_name, sec)                                  \
  case ty_enum:                                                                \
    ProgObj->setSection("obj" #ty_name);                                       \
    assert(EntryFn->getSection().startswith(sec) && "invalid section name");   \
    break;
#define IU_PROG_TYPE_2(ty_enum, ty_name, sec1, sec2)                           \
  case ty_enum:                                                                \
    ProgObj->setSection("obj" #ty_name);                                       \
    assert((EntryFn->getSection().startswith(sec1) ||                          \
            EntryFn->getSection().startswith(sec2)) &&                         \
           "invalid section name");                                            \
    break;
#include "llvm/Transforms/InnerUnikernels/IUProgType.def"
#undef IU_PROG_TYPE_1
#undef IU_PROG_TYPE_2
  default:
    llvm_unreachable("Unknown prog type");
  }
}

/// Performs the actual insertion of the new function
Function *IUEntryInsertion::insertEntry(Module &M, FunctionCallee &ProgRun,
                                        GlobalVariable *ProgObj, Type *CtxPT,
                                        StringRef Name,
                                        unsigned ProgType) const {
  LLVMContext &C = M.getContext();

  // Argument and return type
  IntegerType *EntryRetty = Type::getInt32Ty(C);
  Type *EntryArgTys[1] = {CtxPT};

  // Declare the function in module
  FunctionType *EntryTy = FunctionType::get(EntryRetty, EntryArgTys, false);
  FunctionCallee Entry = M.getOrInsertFunction(Name, EntryTy, getIUFnAttr(C));

  // Setup attributes
  Function *EntryFn = cast<Function>(Entry.getCallee());

  // Construct function body, starting with entry BB
  BasicBlock *EntryBB = BasicBlock::Create(C, "start", EntryFn);
  IRBuilder<> InstBuilder(EntryBB);

  // Bitcast away the packed attribute
  Type *SelfType = ProgRun.getFunctionType()->getParamType(0);
  Value *SelfObj = InstBuilder.CreateBitCast(ProgObj, SelfType);

  // Construct call to prog_run
  Value *ProgRunArgs[2] = {SelfObj, EntryFn->getArg(0)};
  CallInst *ProgRunCI = InstBuilder.CreateCall(
      ProgRun.getFunctionType(), ProgRun.getCallee(), ProgRunArgs);

  // Return
  InstBuilder.CreateRet(ProgRunCI);

  validateAndFinalizeSection(EntryFn, ProgObj, ProgType);

  NumInserted++;

  return EntryFn;
}

/// Sets all the needed attribute for the Rust IU programs
AttributeList IUEntryInsertion::getIUFnAttr(LLVMContext &C) const {

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
  AttributeList AS;
  AS = AS.addFnAttribute(C, Attribute::AttrKind::NoRedZone)
           .addFnAttribute(C, Attribute::AttrKind::NoUnwind)
           .addFnAttribute(C, Attribute::AttrKind::NonLazyBind)
           .addFnAttribute(C, "probe-stack", "__rust_probestack")
           .addFnAttribute(C, "target-cpu", "x86-64")
           .addFnAttribute(C, "target-features", TargetFeatureSs.str())
           .addFnAttribute(C, "tune-cpu", "generic");
  return AS;
}

/// Mark the Variables (i.e. inserted functions and iu-prog objects) as
/// used as these symbols are typically considered as dead code during the
/// linking stage if the '--gc-sections' option is supplied to the linker.
/// Marking the symbols as used would add the 'SHF_GNU_RETAIN' flag and
/// prevent the linker from stripping them away.
/// See also TargetLoweringObjectFileELF::getExplicitSectionGlobal and
/// collectUsedGlobalVariables
void IUEntryInsertion::markUsedGlobalVariables(Module &M,
                                               ArrayRef<Constant *> Vec) const {
  LLVMContext &C = M.getContext();
  const char *UsedName = "llvm.used";

  // Create initializer for @llvm.used
  PointerType *UsedInitElemTy = Type::getInt8Ty(C)->getPointerTo();
  ArrayType *UsedInitArrayTy = ArrayType::get(UsedInitElemTy, Vec.size());
  Constant *UsedInit = ConstantArray::get(UsedInitArrayTy, Vec);

  // FIXME: Do not handle existing @llvm.used for now
  assert(!M.getNamedValue(UsedName) && "@llvm.used exists!");

  // Create @llvm.used in the module with initializer
  Constant *UsedConst = M.getOrInsertGlobal(UsedName, UsedInitArrayTy, [&] {
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
bool IUEntryInsertion::runOnModule(Module &M) const {
  bool Changed = false; // Whether transformation is actually made
  LLVMContext &C = M.getContext();
  SmallVector<Constant *, 8> UsedGV;
  PointerType *Int8PtrTy = Type::getInt8Ty(C)->getPointerTo();

  // Perform stack depth instrumentation
  Changed |= instrumentStack(M, C);

  NamedMDNode *NamedMD = M.getOrInsertNamedMetadata("iu-programs");

  LLVMContext &Context = M.getContext();

  // Traverse all Global variables
  for (GlobalVariable &G : M.globals()) {
    if (G.hasSection() && G.getSection().startswith("inner_unikernel")) {
      Constant *Init = G.getInitializer();
      auto *CS = cast<ConstantStruct>(Init);

      // rtti
      Constant *OP0 = CS->getOperand(0);
      auto *OP0Cda = cast<ConstantDataArray>(OP0);
      const char *RawRTTI = OP0Cda->getRawDataValues().data();
      auto RTTI = *reinterpret_cast<const int *>(RawRTTI);

      std::string ProgRunName;
      switch (RTTI) {
#define IU_PROG_TYPE_1(ty_enum, ty_name, sec)                                  \
  case ty_enum:                                                                \
    ProgRunName = "__iu_entry_" #ty_name;                                      \
    break;
#define IU_PROG_TYPE_2(ty_enum, ty_name, sec1, sec2)                           \
  case ty_enum:                                                                \
    ProgRunName = "__iu_entry_" #ty_name;                                      \
    break;
#include "llvm/Transforms/InnerUnikernels/IUProgType.def"
#undef IU_PROG_TYPE_1
#undef IU_PROG_TYPE_2
      default:
        errs() << "Unknown RTTI " << RTTI << "\n";
      }

      // prog_fn
      Constant *OP1 = CS->getOperand(1);
      auto *OP1CE = cast<ConstantExpr>(OP1);

      Type *OP1SrcTy = OP1CE->getOperand(0)->getType();
      Type *OP1PointeeT = OP1SrcTy->getNonOpaquePointerElementType();

      FunctionType *ProgFuncTy = cast<FunctionType>(OP1PointeeT);
      Type *ProgSelfTy = ProgFuncTy->getParamType(0);

      SmallVector<Type *, 0> CtxTys;
      PointerType *CtxPT = StructType::get(C, CtxTys)->getPointerTo();

      Type *ProgRunArgTys[2] = {ProgSelfTy, CtxPT};
      IntegerType *ProgRunRetty = Type::getInt32Ty(C);

      FunctionType *ProgRunTy =
          FunctionType::get(ProgRunRetty, ProgRunArgTys, false);
      FunctionCallee ProgRun =
          M.getOrInsertFunction(ProgRunName, ProgRunTy, getIUFnAttr(C));

      // name: &'a str
      Constant *OP2 = CS->getOperand(2);
      auto *OP2CE = cast<ConstantExpr>(OP2);

      Constant *ProgNameInit =
          cast<GlobalVariable>(OP2CE->getOperand(0))->getInitializer();
      auto *ProgNameStruct = cast<ConstantStruct>(ProgNameInit);
      auto *ProgNameCda =
          cast<ConstantDataArray>(ProgNameStruct->getOperand(0));
      std::string ProgName(ProgNameCda->getRawDataValues().data(),
                           ProgNameCda->getType()->getNumElements());

      // Add inserted program name metadata to backend pass
      if (auto *FunOP1 = dyn_cast<Function>(OP1CE->getOperand(0))) {
        StringRef UserProg = FunOP1->getName();
        Metadata *Str = MDString::get(Context, UserProg);
        MDNode *Node = MDNode::get(Context, Str);
        NamedMD->addOperand(Node);
      }

      // Add the function using the extracted information above
      Function *EntryFunc = insertEntry(M, ProgRun, &G, CtxPT, ProgName, RTTI);
      Constant *EntryFuncInt8Ptr =
          ConstantExpr::getBitCast(EntryFunc, Int8PtrTy);
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

bool IUEntryInsertion::instrumentStack(Module &M, LLVMContext &C) const {
  SmallVector<Instruction *, 32> WorkList;
  bool HasIndirect = false;

  // Find all calls to other functions
  for (auto &F : M) {
    std::string Demangled;
    nonMicrosoftDemangle(F.getName().data(), Demangled);
    if (StringRef(Demangled).startswith(StringRef("inner_unikernel_rt::")))
      continue;
    for (auto &I : instructions(F)) {
      if (auto *CI = dyn_cast<CallBase>(&I)) {
        HasIndirect |= CI->isIndirectCall();
        WorkList.push_back(CI);
      }
    }
  }

  if (!HasIndirect || WorkList.empty())
    return false;

  // Add metadata to backend pass
  if (HasIndirect) {
    NamedMDNode *NamedMD = M.getOrInsertNamedMetadata("iu-stack");
    LLVMContext &Context = M.getContext();
    Metadata *Str = MDString::get(Context, "iu-indirect-call");
    MDNode *Node = MDNode::get(Context, Str);
    NamedMD->addOperand(Node);
  }

  FunctionType *CheckStackTy = FunctionType::get(Type::getVoidTy(C), {}, false);
  FunctionCallee CheckStack =
      M.getOrInsertFunction("__iu_check_stack", CheckStackTy, getIUFnAttr(C));

  // Add the stack pointer instrumentation
  for (auto *I : WorkList) {
    IRBuilder<> InstBuilder(I);
    InstBuilder.CreateCall(CheckStack);
  }

  return true;
}

/**
 * @brief Checks if the given CallGraph contains a cycle.
 *
 * @param CG The call graph to check for cycles.
 * @return Returns 'true' if the CallGraph contains a cycle, otherwise 'false'.
 *
 */
bool IUEntryInsertion::containsCycle(CallGraph &CG) const {

  std::set<CallGraphNode *> VisitedNodes;
  std::set<CallGraphNode *> NodesInStack;
  std::stack<CallGraphNode *> DfsStack;

  for (auto &KV : CG) {
    CallGraphNode *StartNode = KV.second.get();

    if (VisitedNodes.find(StartNode) != VisitedNodes.end()) {
      continue;
    }

    DfsStack.push(StartNode);

    while (!DfsStack.empty()) {
      CallGraphNode *Node = DfsStack.top();
      DfsStack.pop();

      if (VisitedNodes.find(Node) == VisitedNodes.end()) {
        VisitedNodes.insert(Node);
        NodesInStack.insert(Node);

        for (auto &Neighbor : *Node) {
          CallGraphNode *Child = Neighbor.second;
          if (!Child)
            continue;

          if (NodesInStack.find(Child) != NodesInStack.end()) {
            return true;
          }

          if (VisitedNodes.find(Child) == VisitedNodes.end()) {
            DfsStack.push(Child);
          }
        }
      }

      NodesInStack.erase(Node);
    }
  }

  return false;
}

/// Wrapper for the new pass manager
PreservedAnalyses IUEntryInsertion::run(Module &M, ModuleAnalysisManager &AM) {
  // Run entry insertion pass
  bool Changed = runOnModule(M);
  CallGraph &CG = AM.getResult<CallGraphAnalysis>(M);
  Recursive = containsCycle(CG);

  if (Recursive) {
    errs() << "Found recursive call graph with Module " << M.getName() << "\n";
    NamedMDNode *NamedMD = M.getOrInsertNamedMetadata("iu-stack");
    LLVMContext &Context = M.getContext();
    Metadata *Str = MDString::get(Context, "iu-recursion");
    MDNode *Node = MDNode::get(Context, Str);
    NamedMD->addOperand(Node);
  }

  // Invalidate all analysis if any new code has been added
  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
