package main

type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"-"`
	Role         string `json:"role"` // "owner" or "admin"
	CreatedAt    int64  `json:"created_at"`
}

type Rule struct {
	ID            int64  `json:"id"`
	Owner         string `json:"owner"`
	Name          string `json:"name"`
	Role          string `json:"role"` // local | server | client
	Mode          string `json:"mode"` // tcp | aes | tls | ws
	Secret        string `json:"secret"`
	Host          string `json:"host"` // SNI/Host for tls & ws (optional)
	ListenPort    int    `json:"listen_port"`
	TargetIP      string `json:"target_ip"`
	TargetPort    int    `json:"target_port"`
	LimitBytes    int64  `json:"limit_bytes"`
	BytesUp       int64  `json:"bytes_up"`
	BytesDown     int64  `json:"bytes_down"`
	Period        string `json:"period"`
	PeriodResetAt int64  `json:"period_reset_at"`
	ExpiryDate    int64  `json:"expiry_date"`
	Note          string `json:"note"`
	Active        bool   `json:"active"`
	CreatedAt     int64  `json:"created_at"`

	// Multi-IP ICMP (only used when mode == "icmp"). Empty means "default":
	// kernel-chosen source, accept on any local IP, reply to the request source.
	ICMPSrcIP    string `json:"icmp_src_ip"`    // local IP to send ICMP from
	ICMPListenIP string `json:"icmp_listen_ip"` // local IP to receive peer ICMP on
	ICMPPeerIP   string `json:"icmp_peer_ip"`   // peer IP to send ICMP to

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
