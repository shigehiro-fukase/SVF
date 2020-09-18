#include "DDA/DDAPass.h"
#include "Graphs/SVFG.h"
#include "SVF-FE/LLVMUtil.h"
#include "SVF-FE/PAGBuilder.h"
#include "WPA/Andersen.h"
#include "llvm/IR/DebugInfoMetadata.h"

using namespace llvm;
using namespace std;
using namespace SVF;

static llvm::cl::opt<std::string>
    InputFilename(cl::Positional, llvm::cl::desc("<input bitcode>"),
                  llvm::cl::init("-"));

static llvm::cl::opt<bool>
    SaveFile("save",
             llvm::cl::desc("Save access type and call information to file"));

static llvm::cl::opt<bool>
    IgnoreGEP("ignore-gep",
             llvm::cl::desc("Ignore getelementptr instructions"));

typedef struct _Location {
  uint32_t Line;
  uint32_t Column;
  StringRef SourceFile;

  void setLocation(uint32_t L, uint32_t C, StringRef S) {
    Line = L;
    Column = C;
    SourceFile = S;
  }
} Location;

enum class InstType { UNKNOWN, LOAD, STORE, CALL };

bool getLocation(Location &Loc, InstType &Type, const Value *val,
                 bool isTarget) {
  if (!val)
    return false;

  if (const Instruction *inst = SVFUtil::dyn_cast<Instruction>(val)) {
    if (SVFUtil::isa<AllocaInst>(inst)) {
      for (llvm::DbgInfoIntrinsic *DII :
           FindDbgAddrUses(const_cast<Instruction *>(inst))) {
        if (llvm::DbgDeclareInst *DDI =
                SVFUtil::dyn_cast<llvm::DbgDeclareInst>(DII)) {
          llvm::DIVariable *DIVar =
              SVFUtil::cast<llvm::DIVariable>(DDI->getVariable());
          auto DL = DDI->getDebugLoc();
          Loc.setLocation(DL->getLine(), DL->getColumn(), DL->getFilename());
          return false;
        }
      }
    } else if (MDNode *N = inst->getMetadata("dbg")) {
      llvm::DILocation *DIL =
          SVFUtil::cast<llvm::DILocation>(N); // DILocation is in DebugInfo.h
      Loc.setLocation(DIL->getLine(), DIL->getColumn(), DIL->getFilename());
      if (SVFUtil::isa<LoadInst>(inst)) {
        Type = InstType::LOAD;
      } else {
        Type = InstType::STORE;
      }
      return true;
    }
  }
  if (isTarget) {
    if (const GlobalVariable *gvar = SVFUtil::dyn_cast<GlobalVariable>(val)) {
      NamedMDNode *CU_Nodes =
          gvar->getParent()->getNamedMetadata("llvm.dbg.cu");
      if (CU_Nodes) {
        for (unsigned i = 0, e = CU_Nodes->getNumOperands(); i != e; ++i) {
          llvm::DICompileUnit *CUNode =
              SVFUtil::cast<llvm::DICompileUnit>(CU_Nodes->getOperand(i));
          for (llvm::DIGlobalVariableExpression *GV :
               CUNode->getGlobalVariables()) {
            llvm::DIGlobalVariable *DGV = GV->getVariable();
            if (DGV->getName() == gvar->getName()) {
              Loc.setLocation(DGV->getLine(), 0, DGV->getFilename());
              Type = InstType::LOAD;
              return true;
            }
          }
        }
      }
    } else if (const Function *func = SVFUtil::dyn_cast<Function>(val)) {
      if (llvm::DISubprogram *SP = func->getSubprogram()) {
        if (SP->describes(func)) {
          Loc.setLocation(SP->getLine(), 0, SP->getFilename());
        }
      } else {
        Loc.setLocation(-1, 0, "#External");
      }
      return true;
    }
  }
  return false;
}

class SVFPAContext {
  bool SaveFile;
  llvm::raw_fd_ostream *OSFuncCalls;
  llvm::raw_fd_ostream *OSVarAccess;

public:
  SVFPAContext() : SVFPAContext(nullptr, nullptr, false) {}

  SVFPAContext(llvm::raw_fd_ostream *OSF, llvm::raw_fd_ostream *OSV, bool Save)
      : OSFuncCalls(OSF), OSVarAccess(OSV), SaveFile(Save) {}

  ~SVFPAContext() {
    if (OSFuncCalls)
      OSFuncCalls->close();
    if (OSVarAccess)
      OSVarAccess->close();
  }

  bool isSaveFile() { return SaveFile; }
  llvm::raw_fd_ostream &getOSFuncCall() { return *OSFuncCalls; }
  llvm::raw_fd_ostream &getOSVarAccess() { return *OSVarAccess; }
};

typedef struct {
  Location Loc;
  const Value *Val;
  std::string AccessPtrName;
} PTAVar;

class VariableAccess {
  InstType Type;
  Location Loc;
  bool Valid;
  const PAGNode *SourceNode;
  const SVF::Function *Func;

  std::vector<PTAVar> TargetLocs;

public:
  VariableAccess(const PAGNode *N, bool FP) : VariableAccess() { set(N, FP); }
  VariableAccess() : Valid(false), Type(InstType::UNKNOWN) {}
  ~VariableAccess() = default;

  static std::string getSourceFileName(StringRef S);

  void dump(void);
  void save(SVFPAContext &context);

  void set(const PAGNode *N, bool FP) {
    if (getLocation(Loc, Type, N->getValue(), false)) {
      Valid = true;
    }
    if (FP) {
      Type = InstType::CALL;
    }
    SourceNode = N;
    Func = N->getFunction();
  }
  const Value *getValue(void) const { return SourceNode->getValue(); }
  const PAGNode *getNode(void) const { return SourceNode; }
  const SVF::Function *getFunction(void) const { return Func; }
  void setType(InstType T) { Type = T; }
  void setLocation(Location &L) { Loc = L; }
  void setLocation(uint32_t line, uint32_t col, StringRef S) {
    Loc.Line = line;
    Loc.Column = col;
    Loc.SourceFile = S;
  }
  InstType getType(void) const { return Type; }
  std::string getFilename(void) const {
    return getSourceFileName(Loc.SourceFile);
  }
  uint32_t getLine(void) const { return Loc.Line; }
  uint32_t getColumn(void) const { return Loc.Column; }
  bool isValid(void) const { return Valid; }
  bool isFunctionCall(void) const { return Type == InstType::CALL; }
  bool hasTargets(void) const { return TargetLocs.size() > 0; }

  StringRef getAccessTypeName() const {
    if (Type == InstType::CALL)
      return "CALL";
    else if (Type == InstType::LOAD)
      return "READ";
    else if (Type == InstType::STORE)
      return "WRITE";
    return "UNKNOWN";
  }

  static StringRef getAccessPtrName(const Value *V) {
    StringRef Name;
    if (auto LI = dyn_cast<LoadInst>(V)) {
      if (auto *GEP = dyn_cast<GetElementPtrInst>(LI->getOperand(0))) {
        Name = GEP->getOperand(0)->getName();
        if (Name.empty()) {
          return getAccessPtrName(GEP->getOperand(0));
        }
        if (!Name.empty() && Name[0] == '.') {
          Name = "#Unknown";
        }
      } else if (LI->getOperand(0)->getType()->isPointerTy()) {
        Name = LI->getOperand(0)->getName();
        if (Name.empty()) {
          if (auto *GEP = dyn_cast<GetElementPtrInst>(LI->getOperand(0))) {
            Name = GEP->getOperand(0)->getName();
          }
        }
      }
    }
    return Name;
  }

  static StringRef getAccessPtrName(const PAGNode *N) {
    if (auto LI = dyn_cast<LoadInst>(N->getValue())) {
      return getAccessPtrName(LI);
    } else if (auto GEP = dyn_cast<GetElementPtrInst>(N->getValue())) {
      StringRef Name = GEP->getOperand(0)->getName();
      if (Name.empty()) {
        for (auto E : N->getInEdges()) {
          if (auto SrcNode = E->getSrcNode()) {
            Name = getAccessPtrName(SrcNode);
            if (!Name.empty()) {
              break;
            }
          }
        }
      }
      return Name;
    }
    return "";
  }

  void addTarget(const PAGNode *N) {
    Location L;
    InstType T;
    if (getLocation(L, T, N->getValue(), true)) {
      PTAVar PV;
      PV.Loc = L;
      PV.Val = N->getValue();
      PV.AccessPtrName = getAccessPtrName(getNode()).str();
      if (IgnoreGEP && isa<GetElementPtrInst>(getNode()->getValue())) {
          return;
      }
      TargetLocs.push_back(PV);
    }
  }
};

void VariableAccess::dump(void) {
  if (!isValid())
    return;

  for (auto T : TargetLocs) {
    if (isFunctionCall()) {
      uint32_t line = T.Loc.Line;
      llvm::outs() << "<FuncCall>:  ";
      llvm::outs() << getFunction()->getName().str() << "," << getFilename()
                   << "," << getLine() << "," << getColumn() << ",";
      llvm::outs() << T.AccessPtrName << ",";
      llvm::outs() << T.Val->getName().str();
    } else {
      llvm::outs() << "<VarAccess>: ";
      llvm::outs() << T.AccessPtrName << ",";
      llvm::outs() << T.Val->getName().str() << ","
                   << getSourceFileName(T.Loc.SourceFile) << ",";
      // Source
      llvm::outs() << getAccessTypeName() << "," << getFilename() << ",";
      uint32_t line = getLine();
      uint32_t col  = getColumn();
      if (line == (uint32_t)-1) {
        llvm::outs() << "N/A";
      } else {
        llvm::outs() << line;
      }
      llvm::outs() << "," << col;
    }
    llvm::outs() << "\n";
  }
}

void VariableAccess::save(SVFPAContext &context) {
  if (!isValid() || TargetLocs.empty())
    return;

  llvm::raw_fd_ostream &OSF(context.getOSFuncCall());
  llvm::raw_fd_ostream &OSV(context.getOSVarAccess());

  for (auto T : TargetLocs) {
    if (isFunctionCall()) {
      OSF << getFunction()->getName().str()             // CSV row[0] (required) The caller function name
          << "," << getFilename()                       // CSV row[1] (required) File name that defines the caller function
          << "," << getLine()                           // CSV row[2] (optional) Line number of the function being called 
          << "," << getColumn()                         // CSV row[3] (optional) Column number of the function being called
          << "," << T.Val->getName().str()              // CSV row[4] (required) The name that the function being called
          << "," << "#UNKNOWN"                          // CSV row[5] (required) File name that defines the function being called
          << "\n";
    } else {
      OSV << T.Val->getName().str()                     // CSV row[0] (required) Variable name being accessed
          << "," << getSourceFileName(T.Loc.SourceFile) // CSV row[1] (required) File name that defines the variable being accessed
          << "," << "#UNKNOWN"                          // CSV row[2] (optional) The name of the function that defines the variable being accessed
          << "," << getAccessTypeName()                 // CSV row[3] (required) Access type (Write/Read/ ReadModifyWrite)
          << "," << getFunction()->getName().str()      // CSV row[4] (required) The Function name accessing the variable
          << "," << getFilename()                       // CSV row[5] (required) File name that defines the variable being accessed
          << "," << getLine()                           // CSV row[6] (optional) Line number of the file where the variable is accessed
          << "," << getColumn()                         // CSV row[7] (optional) Column number of the file in which the variable is accessed
          << "\n";
    }
  }
}

std::string VariableAccess::getSourceFileName(StringRef S) {
  auto Pos = S.find_last_of('\\');
  if (Pos != std::string::npos) {
    return S.drop_front(Pos + 1);
  }
  return S;
}

template <typename T>
void dumpPts(T *solver, SVFG *svfg, NodeID ptr, const PointsTo &pts,
             SVFPAContext &context) {
  PAG *pag = solver->getPAG();
  const PAGNode *node = pag->getPAGNode(ptr);

  if (SVFUtil::isa<DummyObjPN>(node) || SVFUtil::isa<DummyValPN>(node)) {
    return;
  }

  // Ignore nodes except for pointer
  if (!node->isPointer())
    return;

  VariableAccess Var(node, pag->isFunPtr(node->getId()));
  if (!Var.isValid())
    return;

  // Find variable(s) or function(s) where the node points-to
  for (NodeBS::iterator it = pts.begin(), eit = pts.end(); it != eit; ++it) {
    const PAGNode *n = pag->getPAGNode(*it);
    if (!SVFUtil::isa<ObjPN>(n))
      continue;
    if (n->hasValue()) {
      StringRef TargetName = n->getValue()->getName();
      StringRef Name = node->getValue()->getName();
      if (TargetName != Name) {
        Var.addTarget(n);
      }
    }
  }
  // Try to identify the access type
  if (Var.hasTargets()) {
    auto Def = svfg->getDefSVFGNode(node);
    for (auto OE : Def->getOutEdges()) {
      const auto Dest = OE->getDstNode();
      if (auto E = SVFUtil::dyn_cast<LoadVFGNode>(Dest)) {
        Var.setType(InstType::LOAD);
      } else if (auto E = SVFUtil::dyn_cast<StoreVFGNode>(Dest)) {
        Var.setType(InstType::STORE);
        // Both dest and src are pointer nodes.
        if (E->isPTANode()) {
          if (auto inst = SVFUtil::dyn_cast<Instruction>(
                  E->getPAGDstNode()->getValue())) {
            if (SVFUtil::isa<AllocaInst>(inst)) {
              for (llvm::DbgInfoIntrinsic *DII :
                   FindDbgAddrUses(const_cast<Instruction *>(inst))) {
                if (llvm::DbgDeclareInst *DDI =
                        SVFUtil::dyn_cast<llvm::DbgDeclareInst>(DII)) {
                  // We identify the access type as LOAD, if a STORE destination
                  // node is a local variable
                  if (isa<DILocalVariable>(DDI->getVariable())) {
                    Var.setType(InstType::LOAD);
                  }
                }
              }
            }
          }
        }
      } else {
        Var.setType(InstType::LOAD);
      }
    }
  }
  if (context.isSaveFile()) {
    Var.save(context);
  } else {
    Var.dump();
  }
}

int main(int argc, char **argv) {
  if (auto *opt = static_cast<llvm::cl::opt<bool> *>(
          llvm::cl::getRegisteredOptions().lookup("stat"))) {
    bool &statOpt = opt->getValue();
    statOpt = false;
  }

  int arg_num = 0;
  char **arg_value = new char *[argc];
  std::vector<std::string> moduleNameVec;
  SVFUtil::processArguments(argc, argv, arg_num, arg_value, moduleNameVec);
  cl::ParseCommandLineOptions(arg_num, arg_value,
                              "Whole Program Points-to Analysis\n");

  SVFModule *svfModule =
      LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(moduleNameVec);

#if 1
  /// Build Program Assignment Graph (PAG)
  PAGBuilder builder;
  PAG *pag = builder.build(svfModule);
  auto *solver = AndersenWaveDiff::createAndersenWaveDiff(pag);

  DenseNodeSet pagNodes;
  for (PAG::iterator it = pag->begin(), eit = pag->end(); it != eit; it++) {
    pagNodes.insert(it->first);
  }

  SVFGBuilder svfBuilder;
  SVFG *svfg = svfBuilder.buildFullSVFGWithoutOPT(solver);

  if (SaveFile) {
    std::error_code EC;
    llvm::raw_fd_ostream OSF("Output_Call.csv", EC, llvm::sys::fs::F_None);
    llvm::raw_fd_ostream OSV("Output_VarAccess.csv", EC, llvm::sys::fs::F_None);
    SVFPAContext context(&OSF, &OSV, SaveFile);
    for (NodeID n : pagNodes) {
      dumpPts(solver, svfg, n, solver->getPts(n), context);
    }
  } else {
    SVFPAContext context;
    for (NodeID n : pagNodes) {
      dumpPts(solver, svfg, n, solver->getPts(n), context);
    }
  }

#else
  if (auto *opt = static_cast<llvm::cl::bits<PointerAnalysis::PTATY> *>(
          llvm::cl::getRegisteredOptions().lookup("dfs"))) {
    opt->addValue(PointerAnalysis::FlowS_DDA);
  }
  DDAPass *dda = new DDAPass();
  dda->runOnModule(svfModule);
#endif
  return 0;
}
