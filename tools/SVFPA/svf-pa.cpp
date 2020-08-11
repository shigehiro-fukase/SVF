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
          return true;
        }
      }
    }
  }
  return false;
}

class AccessVariable {
  InstType Type;
  Location Loc;
  bool Valid;
  const Value *SourceValue;
  const SVF::Function *Func;

  std::vector<std::pair<const Value *, Location>> TargetLocs;

public:
  AccessVariable(const PAGNode *N, bool FP) : AccessVariable() { set(N, FP); }
  AccessVariable() : Valid(false), Type(InstType::UNKNOWN) {}
  ~AccessVariable() = default;

  static std::string getSourceFileName(StringRef S);

  void dump(void);

  void set(const PAGNode *N, bool FP) {
    if (getLocation(Loc, Type, N->getValue(), false)) {
      Valid = true;
    }
    if (FP) {
      Type = InstType::CALL;
    }
    SourceValue = N->getValue();
    Func = N->getFunction();
  }
  const Value *getValue(void) const { return SourceValue; }
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

  void addTarget(const PAGNode *N) {
    Location L;
    InstType T;
    if (getLocation(L, T, N->getValue(), true)) {
      std::pair<const Value *, Location> P(N->getValue(), L);
      TargetLocs.push_back(P);
    }
  }
};

void AccessVariable::dump(void) {
  if (!isValid())
    return;

  for (auto T : TargetLocs) {
    if (isFunctionCall()) {
      llvm::outs() << "<FuncCall>:  ";
      llvm::outs() << getFunction()->getName().str() << "," << getFilename()
                   << "," << getLine() << "," << getColumn() << ","
                   << T.first->getName().str() << "," << T.second.Line << ","
                   << T.second.Column;
    } else {
      llvm::outs() << "<VarAccess>: ";
      llvm::outs() << T.first->getName().str() << ","
                   << getSourceFileName(T.second.SourceFile) << ",";
      // Source
      llvm::outs() << getAccessTypeName() << "," << getFilename() << ","
                   << getLine() << "," << getColumn();
    }
    llvm::outs() << "\n";
  }
}

std::string AccessVariable::getSourceFileName(StringRef S) {
  auto Pos = S.find_last_of('\\');
  if (Pos != std::string::npos) {
    return S.drop_front(Pos + 1);
  }
  return S;
}

template <typename T>
void dumpPts(T *solver, SVFG *svfg, NodeID ptr, const PointsTo &pts) {
  PAG *pag = solver->getPAG();
  const PAGNode *node = pag->getPAGNode(ptr);

  if (SVFUtil::isa<DummyObjPN>(node) || SVFUtil::isa<DummyValPN>(node)) {
    return;
  }

  // Ignore nodes except for pointer
  if (!node->isPointer())
    return;

  AccessVariable Var(node, pag->isFunPtr(node->getId()));
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
  Var.dump();
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

  for (NodeID n : pagNodes) {
    dumpPts(solver, svfg, n, solver->getPts(n));
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
