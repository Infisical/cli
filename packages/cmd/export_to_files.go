/*
Copyright (c) 2023 Infisical Inc.
*/
package cmd

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/Infisical/infisical-merge/packages/util"
)

func normalizeSecretPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if len(path) > 1 {
		path = strings.TrimRight(path, "/")
	}
	return path
}

// isSafeFolderSegment guards against a server returning a folder name that would
// escape the target directory once mirrored into the filesystem (e.g. ".." or a
// name containing a path separator).
func isSafeFolderSegment(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	return !strings.ContainsAny(name, "/\\")
}

// expandToFilePaths resolves the export --path pattern into the concrete secret
// paths a .env file should be written for:
//   - a pattern ending in "/*" expands to the immediate child folders of its prefix
//     (e.g. "apps/*" -> "/apps/cli", "/apps/api")
//   - the root path ("/" or empty) expands to every folder in the tree, recursively
//   - any other pattern is treated as a single concrete path
//
// listChildren returns the immediate child folder paths of the given parent path.
func expandToFilePaths(pattern string, listChildren func(parent string) ([]string, error)) ([]string, error) {
	if strings.HasSuffix(strings.TrimSpace(pattern), "/*") {
		parent := normalizeSecretPath(strings.TrimSuffix(strings.TrimSpace(pattern), "/*"))
		return listChildren(parent)
	}

	path := normalizeSecretPath(pattern)
	if path == "/" {
		return walkFolderTree("/", listChildren)
	}
	return []string{path}, nil
}

func walkFolderTree(root string, listChildren func(parent string) ([]string, error)) ([]string, error) {
	return walkFolderTreeVisited(root, listChildren, map[string]bool{})
}

func walkFolderTreeVisited(
	root string,
	listChildren func(parent string) ([]string, error),
	visited map[string]bool,
) ([]string, error) {
	if visited[root] {
		return nil, nil
	}
	visited[root] = true

	paths := []string{root}
	children, err := listChildren(root)
	if err != nil {
		return nil, err
	}
	for _, child := range children {
		descendants, err := walkFolderTreeVisited(child, listChildren, visited)
		if err != nil {
			return nil, err
		}
		paths = append(paths, descendants...)
	}
	return paths, nil
}

// mapPathToFile maps a secret path to the relative file path its output is written
// to, mirroring the logical folder path into the filesystem (e.g. "/apps/cli" with
// dotenv format -> "apps/cli/.env"). The root path maps to the default filename in
// the current directory.
func mapPathToFile(secretPath, format string) string {
	clean := strings.Trim(secretPath, "/")
	filename := getDefaultFilename(format)
	if clean == "" {
		return filename
	}
	return filepath.Join(clean, filename)
}

func runExportToFiles(request models.GetAllSecretsParameters, format string, tagSlugs string, secretOverriding bool) error {
	listChildren := func(parent string) ([]string, error) {
		folders, err := util.GetAllFolders(models.GetAllFoldersParameters{
			WorkspaceId:              request.WorkspaceId,
			Environment:              request.Environment,
			FoldersPath:              parent,
			InfisicalToken:           request.InfisicalToken,
			UniversalAuthAccessToken: request.UniversalAuthAccessToken,
		})
		if err != nil {
			return nil, err
		}
		base := strings.TrimRight(parent, "/")
		paths := make([]string, 0, len(folders))
		for _, folder := range folders {
			if !isSafeFolderSegment(folder.Name) {
				return nil, fmt.Errorf(
					"refusing to export: server returned unsafe folder name %q", folder.Name,
				)
			}
			paths = append(paths, base+"/"+folder.Name)
		}
		return paths, nil
	}

	paths, err := expandToFilePaths(request.SecretsPath, listChildren)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		util.PrintfStderr("No folders matched path %q; nothing to export\n", request.SecretsPath)
		return nil
	}

	for _, path := range paths {
		pathRequest := request
		pathRequest.SecretsPath = path

		secrets, err := util.GetAllEnvironmentVariables(pathRequest, "")
		if err != nil {
			return fmt.Errorf("unable to fetch secrets for path %s: %w", path, err)
		}

		if secretOverriding {
			secrets = util.OverrideSecrets(secrets, util.SECRET_TYPE_PERSONAL)
		} else {
			secrets = util.OverrideSecrets(secrets, util.SECRET_TYPE_SHARED)
		}
		secrets = util.FilterSecretsByTag(secrets, tagSlugs)
		secrets = util.SortSecretsByKeys(secrets)

		output, err := formatEnvs(secrets, format)
		if err != nil {
			return err
		}

		outputFile := mapPathToFile(path, format)
		if err := writeToFile(outputFile, output, 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", outputFile, err)
		}

		util.PrintfStderr("Exported %d secrets from %s to %s\n", len(secrets), path, outputFile)
	}

	return nil
}
