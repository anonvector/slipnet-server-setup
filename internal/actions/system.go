package actions

func init() {
	Register(&Action{
		ID:       SystemInstall,
		Name:     "Install",
		Category: "system",
		Inputs: []InputField{
			{Key: "bin-dir", Label: "Offline binary directory"},
		},
	})

	Register(&Action{
		ID:       SystemUninstall,
		Name:     "Uninstall",
		Category: "system",
	})

	Register(&Action{
		ID:       SystemUpdate,
		Name:     "Update",
		Category: "system",
	})

	Register(&Action{
		ID:       SystemUsers,
		Name:     "Users",
		Category: "system",
		Inputs: []InputField{
			{Key: "action", Label: "Action", Required: true, Options: []SelectOption{
				{Value: "add", Label: "Add user"},
				{Value: "remove", Label: "Remove user"},
				{Value: "list", Label: "List users"},
			}},
			{Key: "username", Label: "Username", DependsOn: "action"},
		},
	})

	Register(&Action{
		ID:       ConfigExport,
		Name:     "Export Config",
		Category: "config",
	})

	Register(&Action{
		ID:       ConfigImport,
		Name:     "Import Config",
		Category: "config",
		Inputs: []InputField{
			{Key: "path", Label: "Config file path", Required: true},
		},
	})
}
