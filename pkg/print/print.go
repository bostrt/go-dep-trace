package print

import (
	"fmt"
	"golang.org/x/tools/go/callgraph"
	"github.com/xlab/treeprint"
)

func TreePrint(graph *callgraph.Graph) {
	tree := treeprint.New()
	for _,node := range graph.Nodes {
		if len(node.Out) == 0 {
			continue
		}
		t := tree.AddBranch(node.Func.String())
		for _,e := range node.Out {
			t.AddNode(e.Callee.Func.String())
		}
	}

	fmt.Println(tree.String())
}