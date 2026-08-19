package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"k8s.io/client-go/tools/clientcmd"
	k8sapi "k8s.io/client-go/tools/clientcmd/api"
)

// maxKubeContextLen keeps a context name to a length kubectl and the instruction document can carry
// comfortably.
const maxKubeContextLen = 200

// writeKubeconfig builds a kubeconfig covering every kubernetes account, or returns "" if none.
//
// It also records each cluster's context name on the account, and which one ended up as the current
// context, so the instructions can tell the agent when a --context flag is needed.
func (s *runSession) writeKubeconfig() (string, error) {
	config := k8sapi.NewConfig()
	taken := make(map[string]bool)

	for i, account := range s.liveAccounts {
		if account.Type != "kubernetes" {
			continue
		}

		name := kubeContextName(account.Path, taken)

		config.Clusters[name] = &k8sapi.Cluster{Server: fmt.Sprintf("http://127.0.0.1:%d", account.Port)}
		config.AuthInfos[name] = &k8sapi.AuthInfo{}
		config.Contexts[name] = &k8sapi.Context{Cluster: name, AuthInfo: name}

		s.liveAccounts[i].KubeContext = name

		if config.CurrentContext == "" {
			config.CurrentContext = name
			s.liveAccounts[i].IsCurrentKubeContext = true
		}
	}

	if config.CurrentContext == "" {
		return "", nil
	}

	// Serialized by client-go rather than assembled as text, so nothing that arrives in an account
	// path can turn into kubeconfig structure. A newline in the wrong place could otherwise add an
	// exec credential plugin, which kubectl runs as a command.
	contents, err := clientcmd.Write(*config)
	if err != nil {
		return "", fmt.Errorf("failed to build kubeconfig: %w", err)
	}

	path := filepath.Join(s.tempDir, "kubeconfig")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		return "", fmt.Errorf("failed to write kubeconfig: %w", err)
	}
	return path, nil
}

// kubeContextName turns an account path into a context name.
//
// The name reaches kubectl and the instruction document, so it is reduced to letters, digits, dots,
// dashes and underscores. Names also have to stay distinct: contexts live in a map, so a repeat would
// overwrite an entry and leave one cluster answering on another one's proxy.
func kubeContextName(path string, taken map[string]bool) string {
	var out strings.Builder
	out.WriteString("infisical-pam-")

	dashed := false
	for _, r := range path {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			out.WriteRune(r)
			dashed = false
		case !dashed:
			out.WriteRune('-')
			dashed = true
		}
	}

	name := strings.TrimRight(out.String(), "-")
	if len(name) > maxKubeContextLen {
		name = strings.TrimRight(name[:maxKubeContextLen], "-")
	}

	unique := name
	for attempt := 2; taken[unique]; attempt++ {
		unique = fmt.Sprintf("%s-%d", name, attempt)
	}
	taken[unique] = true
	return unique
}
