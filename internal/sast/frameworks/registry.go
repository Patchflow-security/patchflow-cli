package frameworks

import (
	"sort"
	"sync"
)

// Registry holds all known framework packs, keyed by canonical framework name.
// It is the single source of truth for which official packs are available.
type Registry struct {
	mu    sync.RWMutex
	packs map[string]Pack
}

// NewRegistry creates an empty pack registry.
func NewRegistry() *Registry {
	return &Registry{packs: make(map[string]Pack)}
}

// Register adds a pack to the registry. A pack with the same name replaces
// the previous one.
func (r *Registry) Register(p Pack) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.packs[p.Name()] = p
}

// Get returns the pack for a framework name, or nil if not registered.
func (r *Registry) Get(name string) Pack {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.packs[name]
}

// Has reports whether a pack is registered for the given framework.
func (r *Registry) Has(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.packs[name]
	return ok
}

// All returns all registered packs, sorted by name for deterministic output.
func (r *Registry) All() []Pack {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Pack, 0, len(r.packs))
	for _, p := range r.packs {
		result = append(result, p)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name() < result[j].Name()
	})
	return result
}

// Names returns the names of all registered packs, sorted.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.packs))
	for n := range r.packs {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// RulesFor returns all rules from the named pack, or nil if the pack is not
// registered.
func (r *Registry) RulesFor(name string) []FrameworkRule {
	p := r.Get(name)
	if p == nil {
		return nil
	}
	return p.Rules()
}

// AllRules returns all rules from all registered packs, sorted by framework
// then rule ID.
func (r *Registry) AllRules() []FrameworkRule {
	packs := r.All()
	var rules []FrameworkRule
	for _, p := range packs {
		rules = append(rules, p.Rules()...)
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Framework != rules[j].Framework {
			return rules[i].Framework < rules[j].Framework
		}
		return rules[i].ID < rules[j].ID
	})
	return rules
}
