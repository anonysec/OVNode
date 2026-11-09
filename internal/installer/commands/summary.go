package commands

func (c *Config) tlsSummary() string {
	switch c.TLSMethod {
	case "selfsigned":
		return "self-signed · turn TLS on in the panel"
	case "letsencrypt":
		return "lets encrypt · " + c.TLSDomain
	case "letsencrypt-ip":
		return "lets encrypt · " + c.TLSDomain + " · short-lived"
	case "custom":
		return "custom · " + c.TLSCert
	default:
		return c.TLSMethod
	}
}
