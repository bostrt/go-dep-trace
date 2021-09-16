package graph

import (
	"github.com/emicklei/dot"
	log "github.com/sirupsen/logrus"
	"golang.org/x/tools/go/callgraph"
)

func ConvertToDot(graph *callgraph.Graph) *dot.Graph {
	dotGraph := dot.NewGraph(dot.Directed)
	nodeCount := 0
	edgeCount := 0

	// Copy Nodes
	for _,n := range graph.Nodes {
		nodeCount++
		// Add Node
		dotNode := dotGraph.Node(n.Func.String())
		dotNode.Attr("Package", n.Func.Pkg.Pkg.Path())
		dotNode.Attr("Name", n.Func.Name())
	}

	// Copy Edges
	callgraph.GraphVisitEdges(graph, func(edge *callgraph.Edge) error {
		edgeCount++
		dotCallee := dotGraph.Node(edge.Callee.Func.String())
		dotCaller := dotGraph.Node(edge.Caller.Func.String())
		found := dotGraph.FindEdges(dotCaller, dotCallee)
		if len(found) == 0 {
			dotGraph.Edge(dotCaller, dotCallee)
		}
		return nil
	})

	log.Debugf("DOT graph contains %d nodes and %d edges", nodeCount, edgeCount)
	return dotGraph
}

