// Dependency graph generation (tree + DOT format).
// Builds a hierarchical dependency graph from flat dependency lists,
// grouping by ecosystem and manifest.
package sbom

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

// DepNode represents a node in the dependency graph.
type DepNode struct {
	Dependency analysis.Dependency
	Children   []*DepNode
	Depth      int
}

// DepGraph represents the full dependency graph.
type DepGraph struct {
	Root  *DepNode
	Nodes map[string]*DepNode // keyed by name@version
}

// BuildDepGraph constructs a dependency graph from a flat dependency list.
// Dependencies are grouped by ecosystem and manifest path, with the root
// project as the top-level node.
func BuildDepGraph(result *analysis.AnalysisResult) *DepGraph {
	graph := &DepGraph{
		Root: &DepNode{
			Depth: 0,
			Dependency: analysis.Dependency{
				Name:  projectNameFromResult(result),
				IsRoot: true,
			},
		},
		Nodes: make(map[string]*DepNode),
	}

	// Group dependencies by ecosystem
	byEcosystem := make(map[analysis.Ecosystem][]analysis.Dependency)
	for _, dep := range result.Dependencies {
		if dep.IsRoot {
			continue
		}
		byEcosystem[dep.Ecosystem] = append(byEcosystem[dep.Ecosystem], dep)
	}

	// Sort ecosystems for deterministic output
	var ecosystems []string
	for eco := range byEcosystem {
		ecosystems = append(ecosystems, string(eco))
	}
	sort.Strings(ecosystems)

	// Create ecosystem-level nodes
	for _, ecoStr := range ecosystems {
		eco := analysis.Ecosystem(ecoStr)
		deps := byEcosystem[eco]

		ecoNode := &DepNode{
			Depth: 1,
			Dependency: analysis.Dependency{
				Name:      string(eco),
				Ecosystem: eco,
				IsDirect:  true,
			},
		}
		graph.Root.Children = append(graph.Root.Children, ecoNode)

		// Sort deps by name for deterministic output
		sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })

		for _, dep := range deps {
			key := dep.Name + "@" + dep.Version
			node := &DepNode{
				Dependency: dep,
				Depth:      2,
			}
			graph.Nodes[key] = node
			ecoNode.Children = append(ecoNode.Children, node)
		}
	}

	return graph
}

// RenderTree produces a text tree representation of the dependency graph.
func (g *DepGraph) RenderTree() string {
	var b strings.Builder
	renderTreeNode(&b, g.Root, "", true)
	return b.String()
}

func renderTreeNode(b *strings.Builder, node *DepNode, prefix string, isLast bool) {
	connector := "├── "
	if isLast {
		connector = "└── "
	}

	if node.Depth == 0 {
		b.WriteString(node.Dependency.Name + "\n")
	} else {
		label := node.Dependency.Name
		if node.Dependency.Version != "" {
			label += "@" + node.Dependency.Version
		}
		if node.Dependency.Ecosystem != "" && node.Depth == 1 {
			label = fmt.Sprintf("[%s] %d packages", label, len(node.Children))
		}
		b.WriteString(prefix + connector + label + "\n")
	}

	for i, child := range node.Children {
		childPrefix := prefix
		if node.Depth > 0 {
			if isLast {
				childPrefix += "    "
			} else {
				childPrefix += "│   "
			}
		}
		renderTreeNode(b, child, childPrefix, i == len(node.Children)-1)
	}
}

// RenderDOT produces a Graphviz DOT representation of the dependency graph.
func (g *DepGraph) RenderDOT() string {
	var b strings.Builder
	b.WriteString("digraph dependencies {\n")
	b.WriteString("  rankdir=LR;\n")
	b.WriteString("  node [shape=box, fontname=\"Helvetica\"];\n")
	b.WriteString("  edge [color=\"#666666\"];\n\n")

	// Root node
	rootID := dotID(g.Root.Dependency.Name)
	b.WriteString(fmt.Sprintf("  %s [label=\"%s\", style=filled, fillcolor=\"#4A90D9\", fontcolor=white];\n",
		rootID, escapeDOTLabel(g.Root.Dependency.Name)))

	// All nodes and edges
	renderDOTNode(&b, g.Root, rootID)

	b.WriteString("}\n")
	return b.String()
}

func renderDOTNode(b *strings.Builder, node *DepNode, parentID string) {
	for _, child := range node.Children {
		childID := dotID(child.Dependency.Name + "@" + child.Dependency.Version)
		label := child.Dependency.Name
		if child.Dependency.Version != "" {
			label += "@" + child.Dependency.Version
		}

		// Node style based on ecosystem
		color := "#E8E8E8"
		switch child.Dependency.Ecosystem {
		case analysis.EcosystemGo:
			color = "#00ADD8"
		case analysis.EcosystemNPM:
			color = "#F7DF1E"
		case analysis.EcosystemPyPI:
			color = "#3776AB"
		case analysis.EcosystemMaven:
			color = "#E76F00"
		case analysis.EcosystemCargo:
			color = "#DEA584"
		}

		fontColor := "black"
		if child.Dependency.Ecosystem == analysis.EcosystemGo {
			fontColor = "white"
		}

		b.WriteString(fmt.Sprintf("  %s [label=\"%s\", style=filled, fillcolor=\"%s\", fontcolor=%s];\n",
			childID, escapeDOTLabel(label), color, fontColor))
		b.WriteString(fmt.Sprintf("  %s -> %s;\n", parentID, childID))

		renderDOTNode(b, child, childID)
	}
}

func dotID(s string) string {
	return "n_" + sanitizeID(s)
}

func sanitizeID(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func escapeDOTLabel(s string) string {
	return strings.ReplaceAll(s, "\"", "\\\"")
}
