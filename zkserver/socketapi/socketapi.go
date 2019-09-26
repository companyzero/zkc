package socketapi

const (
	SocketFilename = ".socket" // socket filename

	SCVersion     = 1             // socket API version
	SCUserEnable  = "userenable"  // ID for SocketCommandUserEnable
	SCUserDisable = "userdisable" // ID for SocketCommandUserDisable
)

// SocketCommandID identifies the command that follows.
type SocketCommandID struct {
	Version uint   `json:"version"`
	Command string `json:"command"`
}

// SocketCommandUserDisable attempts to disable a user. We require a user
// identity here in order to ensure uniqueness.
type SocketCommandUserDisable struct {
	Identity string `json:"identity"` // public identity
}

// SocketCommandUserDisableReply returns "" if the command was successful.
type SocketCommandUserDisableReply struct {
	Error string `json:"error"`
}

// SocketCommandUserEnable attempts to enable a user. We require a user
// identity here in order to ensure uniqueness.
type SocketCommandUserEnable struct {
	Identity string `json:"identity"` // public identity
}

// SocketCommandUserEnableReply returns "" if the command was successful.
type SocketCommandUserEnableReply struct {
	Error string `json:"error"`
}
