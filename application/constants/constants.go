package constants

// BackendVersion and LastCommit are injected at build time.

// BackendVersion 当前后端版本号
var BackendVersion = "4.14.0"

// Edition metadata is always Pro. Feature configuration is managed separately.
// Keep these identifiers for API and frontend compatibility.
const IsPro = "true"

const IsProBool = true

// LastCommit 最后commit id
var LastCommit = "000000"

const (
	APIPrefix      = "/api/v4"
	APIPrefixSlave = "/api/v4/slave"
	CrHeaderPrefix = "X-Cr-"
)

const CloudreveScheme = "cloudreve"

type (
	FileSystemType string
)

const (
	FileSystemMy           = FileSystemType("my")
	FileSystemShare        = FileSystemType("share")
	FileSystemTrash        = FileSystemType("trash")
	FileSystemSharedWithMe = FileSystemType("shared_with_me")
	FileSystemUnknown      = FileSystemType("unknown")
)
