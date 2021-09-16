package graph

import (
	"fmt"
	"github.com/bostrt/go-dep-trace/pkg/filter"
	log "github.com/sirupsen/logrus"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func GetCallGraph(goModPath string, progMainPath string, sourceKeepPkg string, targetKeepPkg string) (*callgraph.Graph, error) {

	log.Info("Generating call graph for", progMainPath)
	graph, err := doCallgraph(goModPath, []string{progMainPath})

	if err != nil {
		return nil, err
	}

	log.Infof("Pre-filter shows %d Nodes", len(graph.Nodes))

	var result int
	result = filter.RemoveNodesBySuffix(graph, ".Error")
	log.Debugf("Removed %d nodes ending with .Error", result)
	result = filter.RemoveNodesByRegex(graph, ".*\\.init\\#\\d+$")
	log.Debugf("Removed %d nodes ending with pattern like .init#1279", result)
	result = filter.RemoveStdLib(graph)
	log.Debugf("Removed %d nodes in a stdlib package", result)
	result = filter.KeepEdgesByPackage(graph, sourceKeepPkg, targetKeepPkg)
	log.Debugf("Removed %d edges with callee outside %s and %s\n", result, targetKeepPkg, sourceKeepPkg)

	// Always run this last :)
	result = filter.RemoveIsolatedNodes(graph)
	log.Debugf("Removed %d isolated nodes", result)

	log.Infof("Post-filter shows %d Nodes", len(graph.Nodes))

	log.Info("Converting to DOT format")
	return graph, nil
}

func doCallgraph(dir string, args []string) (*callgraph.Graph, error) {
	var cg *callgraph.Graph

	cfg := &packages.Config{
		Mode:  packages.LoadAllSyntax,
		Tests: false,
		Dir:   dir,
	}

	initial, err := packages.Load(cfg, args...)
	if err != nil {
		return nil, err
	}
	if packages.PrintErrors(initial) > 0 {
		return nil, fmt.Errorf("packages contain errors")
	}

	// Create and build SSA-form program representation.
	prog, pkgs := ssautil.AllPackages(initial, 0)
	prog.Build()

	mains, err := mainPackages(pkgs)
	if err != nil {
		return nil, err
	}
	var roots []*ssa.Function
	for _, main := range mains {
		roots = append(roots, main.Func("init"), main.Func("main"))
	}
	rtares := rta.Analyze(roots, true)
	cg = rtares.CallGraph

	cg.DeleteSyntheticNodes()

	if err != nil {
		return nil, err
	}

	return cg, nil
}


// https://cs.opensource.google/go/x/tools/+/master:cmd/callgraph/main.go;l=306-319;drc=36045662144327e4475f9d356f49ab32ce730049;bpv=0
// mainPackages returns the main packages to analyze.
// Each resulting package is named "main" and has a main function.
func mainPackages(pkgs []*ssa.Package) ([]*ssa.Package, error) {
	var mains []*ssa.Package
	for _, p := range pkgs {
		if p != nil && p.Pkg.Name() == "main" && p.Func("main") != nil {
			mains = append(mains, p)
		}
	}
	if len(mains) == 0 {
		return nil, fmt.Errorf("no main packages")
	}
	return mains, nil
}
