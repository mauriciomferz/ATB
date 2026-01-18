package atb.poa

# Tests for low-risk allowlist (no PoA required)

# Helper: minimal low-risk input (no PoA)
low_risk_input := {
	"agent": {"spiffe_id": "spiffe://atb.example/agent/task-agent"},
	"poa": {},
	"request": {"method": "GET", "path": "/api/status", "action": "system.status.get"},
	"policy": {"max_ttl_seconds": 300},
}

# Test: allowed low-risk action passes without PoA
test_low_risk_allowlist_status_get if {
	d := decision with input as low_risk_input
	d.allow == true
	d.reason == "allow_low_risk_without_poa"
}

# Test: health check action allowed
test_low_risk_allowlist_health_check if {
	inp := json.patch(low_risk_input, [
		{"op": "replace", "path": "/request/action", "value": "system.health.check"},
		{"op": "replace", "path": "/request/path", "value": "/api/health"},
	])
	d := decision with input as inp
	d.allow == true
	d.reason == "allow_low_risk_without_poa"
}

# Test: FAQ query with POST allowed
test_low_risk_allowlist_faq_post if {
	inp := json.patch(low_risk_input, [
		{"op": "replace", "path": "/request/action", "value": "kb.faq.query"},
		{"op": "replace", "path": "/request/method", "value": "POST"},
	])
	d := decision with input as inp
	d.allow == true
	d.reason == "allow_low_risk_without_poa"
}

# Test: unknown action requires PoA
test_low_risk_unknown_action_denied if {
	inp := json.patch(low_risk_input, [{"op": "replace", "path": "/request/action", "value": "unknown.action"}])
	d := decision with input as inp
	d.allow == false
	d.reason == "poa_required_for_action"
}

# Test: high-risk action (e.g., sap.vendor.change) requires PoA
test_low_risk_high_risk_action_denied if {
	inp := json.patch(low_risk_input, [
		{"op": "replace", "path": "/request/action", "value": "sap.vendor.change"},
		{"op": "replace", "path": "/request/method", "value": "POST"},
	])
	d := decision with input as inp
	d.allow == false
	d.reason == "poa_required_for_action"
}

# Test: safe path /health allowed even without action
test_low_risk_safe_path_health if {
	inp := json.patch(low_risk_input, [
		{"op": "remove", "path": "/request/action"},
		{"op": "replace", "path": "/request/path", "value": "/health"},
	])
	d := decision with input as inp
	d.allow == true
	d.reason == "allow_low_risk_without_poa"
}

# Test: safe path /metrics allowed
test_low_risk_safe_path_metrics if {
	inp := json.patch(low_risk_input, [
		{"op": "remove", "path": "/request/action"},
		{"op": "replace", "path": "/request/path", "value": "/metrics"},
	])
	d := decision with input as inp
	d.allow == true
	d.reason == "allow_low_risk_without_poa"
}

# Test: POST to safe path without action still requires PoA (method mismatch)
test_low_risk_safe_path_wrong_method if {
	inp := json.patch(low_risk_input, [
		{"op": "remove", "path": "/request/action"},
		{"op": "replace", "path": "/request/path", "value": "/health"},
		{"op": "replace", "path": "/request/method", "value": "POST"},
	])
	d := decision with input as inp
	d.allow == false
	d.reason == "poa_required_for_action"
}

# Test: wrong method for allowlisted action denied
test_low_risk_wrong_method_for_action if {
	inp := json.patch(low_risk_input, [
		{"op": "replace", "path": "/request/action", "value": "reporting.dashboard.view"},
		{"op": "replace", "path": "/request/method", "value": "DELETE"},
	])
	d := decision with input as inp
	d.allow == false
	d.reason == "poa_required_for_action"
}
