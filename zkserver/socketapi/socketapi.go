package socketapi

const (
	SocketFilename = ".socket"

	SCVersion     = 1
	SCUserDisable = "userdisable"
)

type SocketCommandID struct {
	Version uint   `json:"version"`
	Command string `json:"command"`
}

type SocketCommandUserDisable struct {
	Identifier string `json:"identifier"` // nick or identity
}

type SocketCommandUserDisableReply struct {
	Error string `json:"error"`
}
