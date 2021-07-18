package alpine

type advisory struct {
	PkgName              string              `json:"name"`
	Secfixes             map[string][]string `json:"secfixes"`
	UnfixVulnerabilities map[string][]string `json:"unfixvulns"`
	Apkurl               string              `json:"apkurl"`
	Archs                []string            `json:"archs"`
	Urlprefix            string              `json:"urlprefix"`
	Reponame             string              `json:"reponame"`
	Distroversion        string              `json:"distroversion"`
}

type unfixAdvisory struct {
	DistroVersion string              `json:"distroversion,omitempty"`
	RepoName      string              `json:"reponame,omitempty"`
	UnfixVersion  map[string][]string `json:"unfix,omitempty"`
	PkgName       string              `json:"name,omitempty"`
}
