package hostcmd

import (
	"encoding/json"
	"io"
)

func hostopsJSON(w io.Writer, v any) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(v)
}
