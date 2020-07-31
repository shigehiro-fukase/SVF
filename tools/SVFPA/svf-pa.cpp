#include "Graphs/SVFG.h"
#include "WPA/Andersen.h"
#include "SVF-FE/LLVMUtil.h"
#include "SVF-FE/PAGBuilder.h"
#include "DDA/DDAPass.h"

using namespace llvm;
using namespace std;
using namespace SVF;

static llvm::cl::opt<std::string> InputFilename(cl::Positional,
        llvm::cl::desc("<input bitcode>"), llvm::cl::init("-"));

/*!
 * An example to print points-to set of an LLVM value
 */
template <typename T>
void dumpPts(T* solver, NodeID ptr, const PointsTo& pts)
{
    PAG* pag = solver->getPAG();
    std::string outStr;
    const PAGNode* node = pag->getPAGNode(ptr);

    StringRef Name;

    /// print the points-to set of node which has the maximum pts size.
    if (SVFUtil::isa<DummyObjPN> (node))
    {
	return;
    }
    else if (!SVFUtil::isa<DummyValPN>(node) && !SVFModule::pagReadFromTXT())
    {
        Name = node->getValue()->getName();
	std::string SLoc(SVFUtil::getSourceLoc(node->getValue()));
	if (SLoc.empty() || SLoc == "{  }")
	    return;

        if (Name.empty())
        {
            // How can we get the name of the node???
        }
        if (pag->isFunPtr(node->getId()))
        {
            for (auto ICS : pag->getIndCallSites(node->getId())) {
                for (auto O : solver->getIndCSCallees(ICS)) {
                    //outStr += O->getName();
                }
            }
            //outStr += "CALL:";
        }
        outStr += ("##<" + Name.str() + "> ");
        outStr += SVFUtil::getSourceLoc(node->getValue());
    }

    NodeID srcNodeId = node->getId();
    int numTarget = 0;
    for (NodeBS::iterator it = pts.begin(), eit = pts.end(); it != eit; ++it)
    {
        const PAGNode* n = pag->getPAGNode(*it);
        if(SVFUtil::isa<ObjPN>(n) == false)
            continue;
        StringRef TargetName = n->getValue()->getName();
        if (TargetName != Name)
        {
            outStr += "\n\t ->";
            outStr += (" <" +  TargetName.str() + "> ");
            outStr += SVFUtil::getSourceLoc(n->getValue());
            numTarget++;
        }
    }
    if (numTarget != 0 && !outStr.empty()) {
        outStr += "\n";
        outs() << outStr;
    }

}

int main(int argc, char ** argv)
{
    if (auto *opt = static_cast<llvm::cl::opt<bool> *>(
	llvm::cl::getRegisteredOptions().lookup("stat"))) {
	bool& statOpt = opt->getValue();
        statOpt = false;
    }

    int arg_num = 0;
    char **arg_value = new char*[argc];
    std::vector<std::string> moduleNameVec;
    SVFUtil::processArguments(argc, argv, arg_num, arg_value, moduleNameVec);
    cl::ParseCommandLineOptions(arg_num, arg_value,
                                "Whole Program Points-to Analysis\n");

    SVFModule* svfModule = LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(moduleNameVec);

#if 1
    /// Build Program Assignment Graph (PAG)
    PAGBuilder builder;
    PAG *pag = builder.build(svfModule);
    auto* solver = AndersenWaveDiff::createAndersenWaveDiff(pag);

    DenseNodeSet pagNodes;
    for(PAG::iterator it = pag->begin(), eit = pag->end(); it!=eit; it++)
    {
        pagNodes.insert(it->first);
    }

    //solver->printIndCSTargets();

    for (NodeID n : pagNodes)
    {
        dumpPts(solver, n, solver->getPts(n));
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
