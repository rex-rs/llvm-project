add_llvm_library( LLVMInnerUnikernels
  IUInsertEntry.cpp

  LINK_COMPONENTS
  Analysis
  Core
  Support
  TransformUtils
  )
