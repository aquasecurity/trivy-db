package photon

type PhotonCVE struct {
	CveID    string  `json:"cve_id"`
	Pkg      string  `json:"pkg"`
	CveScore float64 `json:"cve_score"`
	AffVer   string  `json:"aff_ver"`
	ResVer   string  `json:"res_ver"`
}
