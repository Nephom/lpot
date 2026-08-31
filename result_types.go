package main

type resultReport struct {
	SchemaVersion    int                  `json:"schema_version"`
	Version          string               `json:"version"`
	RunID            string               `json:"run_id"`
	Status           string               `json:"status"`
	Checkpoint       bool                 `json:"checkpoint"`
	Message          string               `json:"message"`
	StartedAt        string               `json:"started_at,omitempty"`
	UpdatedAt        string               `json:"updated_at"`
	FinishedAt       string               `json:"finished_at,omitempty"`
	TotalCycles      int                  `json:"total_cycles"`
	CompletedCycles  int                  `json:"completed_cycles"`
	SuccessfulCycles int                  `json:"successful_cycles"`
	FailedCycles     int                  `json:"failed_cycles"`
	Checks           resultChecks         `json:"checks"`
	Classification   classificationReport `json:"classification"`
	Cycles           []resultCycle        `json:"cycles"`
	Problems         []resultProblem      `json:"problems"`
	Artifacts        map[string]string    `json:"artifacts"`
}

type classificationReport struct {
	Status     string                 `json:"status"`
	Total      int                    `json:"total"`
	Kept       int                    `json:"kept"`
	Skipped    int                    `json:"skipped"`
	Unverified int                    `json:"unverified"`
	Devices    []classificationDevice `json:"devices,omitempty"`
}

type classificationDevice struct {
	BDF          string `json:"bdf"`
	Vendor       string `json:"vendor,omitempty"`
	Device       string `json:"device,omitempty"`
	Class        string `json:"class,omitempty"`
	Header       string `json:"header,omitempty"`
	PCIeCap      string `json:"pcie_capability"`
	LinkCap      string `json:"link_capability"`
	LinkStatus   string `json:"link_status"`
	LspciLinkCap string `json:"lspci_link_capability,omitempty"`
	LspciStatus  string `json:"lspci_link_status,omitempty"`
	Decision     string `json:"decision"`
	Reason       string `json:"reason,omitempty"`
	Verification string `json:"verification"`
}

type resultChecks struct {
	Topology    resultCheck `json:"topology"`
	LSPCI       resultCheck `json:"lspci"`
	ConfigSpace resultCheck `json:"config_space"`
	ConfigNoise resultCheck `json:"config_noise"`
}

type resultCheck struct {
	Status        string `json:"status"`
	ChangedCycles int    `json:"changed_cycles,omitempty"`
	Noteworthy    int    `json:"noteworthy_changes,omitempty"`
	BenignChanges int    `json:"benign_changes,omitempty"`
	Message       string `json:"message,omitempty"`
}

type resultCycle struct {
	Number      int             `json:"number"`
	StartedAt   string          `json:"started_at,omitempty"`
	FinishedAt  string          `json:"finished_at,omitempty"`
	Status      string          `json:"status"`
	Topology    string          `json:"topology"`
	LSPCI       string          `json:"lspci"`
	ConfigSpace string          `json:"config_space"`
	Events      []resultProblem `json:"events,omitempty"`
}

type resultProblem struct {
	Severity   string `json:"severity"`
	Category   string `json:"category"`
	Cycle      int    `json:"cycle,omitempty"`
	Timestamp  string `json:"timestamp,omitempty"`
	BDF        string `json:"bdf,omitempty"`
	Message    string `json:"message"`
	DetailsLog string `json:"details_log,omitempty"`
}

type configResultChange struct {
	cycle     int
	timestamp string
	device    string
	offset    string
	before    string
	after     string
}
