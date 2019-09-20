package socketapi

type SocketCommandID struct {
	Version uint   `json:"version"`
	Command string `json:"command"`
}

const (
	SCVersion     = 1
	SCUserDisable = "userdisable"
)

type SocketCommandUserDisabler struct {
	Identifier string `json:"identifier"` // nick or identity
}

type SocketCommandUserDisablerReply struct {
	Error string `json:"error"`
}
