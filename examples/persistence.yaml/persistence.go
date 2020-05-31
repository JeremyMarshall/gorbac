package main

import (
	"gopkg.in/yaml.v2"
	"log"
	"os"

	"github.com/mikespook/gorbac"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func LoadYaml(filename string, v interface{}) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return yaml.NewDecoder(f).Decode(v)
}

func SaveYaml(filename string, v interface{}) error {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	return yaml.NewEncoder(f).Encode(v)
}

func main() {
	// map[RoleId]PermissionIds
	var yamlRoles map[string][]string
	// map[RoleId]ParentIds
	var yamlInher map[string][]string
	// Load roles information
	if err := LoadYaml("roles.yaml", &yamlRoles); err != nil {
		log.Fatal(err)
	}
	// Load inheritance information
	if err := LoadYaml("inher.yaml", &yamlInher); err != nil {
		log.Fatal(err)
	}
	rbac := gorbac.New()
	permissions := make(gorbac.Permissions)

	// Build roles and add them to goRBAC instance
	for rid, pids := range yamlRoles {
		role := gorbac.NewStdRole(rid)
		for _, pid := range pids {
			_, ok := permissions[pid]
			if !ok {
				permissions[pid] = gorbac.NewStdPermission(pid)
			}
			role.Assign(permissions[pid])
		}
		rbac.Add(role)
	}
	// Assign the inheritance relationship
	for rid, parents := range yamlInher {
		if err := rbac.SetParents(rid, parents); err != nil {
			log.Fatal(err)
		}
	}
	// Check if `editor` can add text
	if rbac.IsGranted("editor", permissions["add-text"], nil) {
		log.Println("Editor can add text")
	}
	// Check if `chief-editor` can add text
	if rbac.IsGranted("chief-editor", permissions["add-text"], nil) {
		log.Println("Chief editor can add text")
	}
	// Check if `photographer` can add text
	if !rbac.IsGranted("photographer", permissions["add-text"], nil) {
		log.Println("Photographer can't add text")
	}
	// Check if `nobody` can add text
	// `nobody` is not exist in goRBAC at the moment
	if !rbac.IsGranted("nobody", permissions["read-text"], nil) {
		log.Println("Nobody can't read text")
	}
	// Add `nobody` and assign `read-text` permission
	nobody := gorbac.NewStdRole("nobody")
	permissions["read-text"] = gorbac.NewStdPermission("read-text")
	nobody.Assign(permissions["read-text"])
	rbac.Add(nobody)
	// Check if `nobody` can read text again
	if rbac.IsGranted("nobody", permissions["read-text"], nil) {
		log.Println("Nobody can read text")
	}

	// Persist the change
	// map[RoleId]PermissionIds
	yamlOutputRoles := make(map[string][]string)
	// map[RoleId]ParentIds
	yamlOutputInher := make(map[string][]string)
	SaveYamlHandler := func(r gorbac.Role, parents []string) error {
		// WARNING: Don't use gorbac.RBAC instance in the handler,
		// otherwise it causes deadlock.
		permissions := make([]string, 0)
		for _, p := range r.(*gorbac.StdRole).Permissions() {
			permissions = append(permissions, p.ID())
		}
		yamlOutputRoles[r.ID()] = permissions
		yamlOutputInher[r.ID()] = parents
		return nil
	}
	if err := gorbac.Walk(rbac, SaveYamlHandler); err != nil {
		log.Fatalln(err)
	}

	// Save roles information
	if err := SaveYaml("new-roles.yaml", &yamlOutputRoles); err != nil {
		log.Fatal(err)
	}
	// Save inheritance information
	if err := SaveYaml("new-inher.yaml", &yamlOutputInher); err != nil {
		log.Fatal(err)
	}
}
