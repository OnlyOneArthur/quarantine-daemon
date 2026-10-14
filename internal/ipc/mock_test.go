package ipc

// StaticStatusProvider provides static status information for tests.
type StaticStatusProvider struct {
	StatusData StatusResponse
}

// Status returns the fixed status payload this provider was built with.
func (s StaticStatusProvider) Status() StatusResponse {
	return s.StatusData
}
