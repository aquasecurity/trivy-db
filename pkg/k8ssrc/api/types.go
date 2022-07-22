package api

type Advisory []OutDatedAPIData

type OutDatedAPIData struct {
	description       string `json:"description"`
	DeprecatedVersion string `json:"deprecated-version"`
	RemovedVersion    string `json:"removed-version"`
	Group             string `json:"group"`
	Version           string `json:"version"`
	Kind              string `json:"kind"`
}
