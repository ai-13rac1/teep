package nearcloud

import (
	"context"
	"encoding/json"

	"github.com/13rac1/teep/internal/provider/neardirect"
)

// ModelLister fetches available models from the NEAR AI /v1/models endpoint.
// Nearcloud serves the same model universe as neardirect.
type ModelLister struct {
	lister *neardirect.ModelLister
}

// NewModelLister returns a ModelLister that delegates to the given neardirect lister.
func NewModelLister(lister *neardirect.ModelLister) *ModelLister {
	return &ModelLister{lister: lister}
}

// ListModels returns all models from the NEAR AI /v1/models endpoint.
func (l *ModelLister) ListModels(ctx context.Context) ([]json.RawMessage, error) {
	return l.lister.ListModels(ctx)
}
