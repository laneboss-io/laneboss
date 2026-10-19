package lane

import "laneboss.io/laneboss/internal/decisionsrv"

// Keep the lane check's private representation while sharing the actual schema
// contract with org inspection and the decision service.
type historySchemaObject struct {
	kind, name, table, statement string
	nullSQL                      bool
}

var historySchema = func() []historySchemaObject {
	var layout []historySchemaObject
	for _, entry := range decisionsrv.HistorySchema() {
		layout = append(layout, historySchemaObject{entry.Kind, entry.Name, entry.Table, entry.Statement, entry.NullSQL})
	}
	return layout
}()
