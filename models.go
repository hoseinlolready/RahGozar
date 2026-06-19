package main

type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"-"`
	Role         string `json:"role"`
	CreatedAt    int64  `json:"created_at"`
}

// Rule is a single port-forward tunnel definition.
type Rule struct {
	ID            int64  `json:"id"`
	Owner         string `json:"owner"` // username of the admin this tunnel belongs to
	Name          string `json:"name"`  // friendly label
	ListenPort    int    `json:"listen_port"`
	TargetIP      string `json:"target_ip"`
	TargetPort    int    `json:"target_port"`
	LimitBytes    int64  `json:"limit_bytes"` // 0 = unlimited, applies to bytes_up+bytes_down
	BytesUp       int64  `json:"bytes_up"`
	BytesDown     int64  `json:"bytes_down"`
	Period        string `json:"period"`          // none | daily | weekly | monthly
	PeriodResetAt int64  `json:"period_reset_at"` // unix ts of next scheduled reset, 0 if period=none
	ExpiryDate    int64  `json:"expiry_date"`     // 0 = never
	Note          string `json:"note"`
	Active        bool   `json:"active"`
	CreatedAt     int64  `json:"created_at"`

	RateUpBps   float64 `json:"rate_up_bps"`
	RateDownBps float64 `json:"rate_down_bps"`
	Status      string  `json:"status"` // computed: active | inactive | expired | limited
}

type SysStats struct {
	MemText      string  `json:"mem_text"`
	MemPercent   int     `json:"mem_percent"`
	CPUPercent   int     `json:"cpu_percent"`
	UptimeText   string  `json:"uptime_text"`
	TotalUpBps   float64 `json:"total_up_bps"`
	TotalDownBps float64 `json:"total_down_bps"`
	ActiveRules  int     `json:"active_rules"`
	TotalRules   int     `json:"total_rules"`
}
