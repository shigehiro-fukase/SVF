#include "SVF-FE/LLVMUtil.h"
#include "Graphs/SVFG.h"
#include "WPA/Andersen.h"
#include "SVF-FE/PAGBuilder.h"

using namespace llvm;
using namespace std;
using namespace SVF;

static llvm::cl::opt<std::string> InputFilename(cl::Positional,
        llvm::cl::desc("<input bitcode>"), llvm::cl::init("-"));

/*!
 * An example to print points-to set of an LLVM value
 */
void dumpPts(PAG* pag, NodeID ptr, const PointsTo& pts)
{
    const PAGNode* node = pag->getPAGNode(ptr);
    /// print the points-to set of node which has the maximum pts size.
    if (SVFUtil::isa<DummyObjPN> (node))
    {
	return;
    }
    else if (!SVFUtil::isa<DummyValPN>(node) && !SVFModule::pagReadFromTXT())
    {
	StringRef Name = node->getValue()->getName();
	if (Name.empty())
	    return;
	std::string SLoc(SVFUtil::getSourceLoc(node->getValue()));
	if (SLoc.empty() || SLoc == "{  }")
	    return;

        outs() << "----------------------------------------------\n";
        outs() << "##<" << Name << "> ";
        outs() << "Source Loc: " << SVFUtil::getSourceLoc(node->getValue());
    }
    outs() << "\nPtr " << node->getId() << " ";

    if (pts.empty())
    {
        outs() << "\t\tPointsTo: {empty}\n\n";
    }
    else
    {
        outs() << "\t\tPointsTo: { ";
        for (PointsTo::iterator it = pts.begin(), eit = pts.end(); it != eit;
                ++it)
            outs() << *it << " ";
        outs() << "}\n\n";
    }

    outs() << "";

    for (NodeBS::iterator it = pts.begin(), eit = pts.end(); it != eit; ++it)
    {
        const PAGNode* node = pag->getPAGNode(*it);
        if(SVFUtil::isa<ObjPN>(node) == false)
            continue;
        NodeID ptd = node->getId();
        outs() << "!!Target NodeID " << ptd << "\t [";
        const PAGNode* pagNode = pag->getPAGNode(ptd);
        if (SVFUtil::isa<DummyValPN>(node))
            outs() << "DummyVal\n";
        else if (SVFUtil::isa<DummyObjPN>(node))
            outs() << "Dummy Obj id: " << node->getId() << "]\n";
        else
        {
            if(!SVFModule::pagReadFromTXT())
            {
                outs() << "<" << pagNode->getValue()->getName() << "> ";
                outs() << "Source Loc: " << SVFUtil::getSourceLoc(pagNode->getValue()) << "] \n";
            }
        }
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

    /// Build Program Assignment Graph (PAG)
    PAGBuilder builder;
    PAG *pag = builder.build(svfModule);

    /// Create Andersen's pointer analysis
    Andersen* ander = AndersenWaveDiff::createAndersenWaveDiff(pag);

    DenseNodeSet pagNodes;
    for(PAG::iterator it = pag->begin(), eit = pag->end(); it!=eit; it++)
    {
        pagNodes.insert(it->first);
    }

    for (NodeID n : pagNodes)
    {
        dumpPts(pag, n, ander->getPts(n));
    }
    
    return 0;
}
