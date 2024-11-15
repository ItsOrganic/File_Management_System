package utils

// AllPermissions contains all valid permissions
var AllPermissions = []string{
	"create_users",
	"update_users",
	"delete_users",
	"view_users",
	"create_spaces",
	"update_spaces",
	"delete_spaces",
	"view_spaces",
	"upload_files",
	"download_files",
	"delete_files",
	"manage_permissions",
}

// ValidatePermissions checks if all provided permissions are valid
func ValidatePermissions(permissions []string) bool {
	permissionMap := make(map[string]bool)
	for _, p := range AllPermissions {
		permissionMap[p] = true
	}

	for _, p := range permissions {
		if !permissionMap[p] {
			return false
		}
	}
	return true
}

// HasPermission checks if the given permissions slice contains the required permission
