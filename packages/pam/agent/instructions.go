package agent

import (
	"fmt"
	"strings"
)

// The username and database a client sends are irrelevant: the gateway overwrites both with the
// real injected credentials before the packet reaches the target. We therefore render a fixed
// placeholder rather than pretending to know the real values, which would require creating a
// session just to print a banner.
const placeholderUser = "pam"
const placeholderDatabase = "postgres"

// LiveAccount is one running proxy, as described to the agent.
type LiveAccount struct {
	Path             string
	Type             string
	TypeLabel        string
	Host             string
	Port             int
	ConnectionString string
	Example          string
	// KubeContext is this cluster's context in the session kubeconfig, for kubernetes accounts.
	KubeContext string
	// IsCurrentKubeContext marks the one kubernetes account plain kubectl commands reach.
	IsCurrentKubeContext bool
	// AwaitingApproval marks an account whose port is bound but which cannot open a session until a
	// reviewer approves the request raised for it.
	AwaitingApproval bool
	// RequiresApproval marks an account behind an approval policy, whether or not it is granted right
	// now. A grant is time-bounded, so even one that works at the start of a run can need approving
	// again before the run is over.
	RequiresApproval bool
}

// connectionFor builds the connection string and a CLI example for a port-based account type.
func connectionFor(accountType string, port int) (connectionString, example string) {
	switch accountType {
	case "postgres":
		return fmt.Sprintf("postgres://%s@127.0.0.1:%d/%s", placeholderUser, port, placeholderDatabase),
			fmt.Sprintf("psql -h 127.0.0.1 -p %d -U %s -d %s", port, placeholderUser, placeholderDatabase)
	case "mysql":
		return fmt.Sprintf("mysql://%s@127.0.0.1:%d", placeholderUser, port),
			fmt.Sprintf("mysql -h 127.0.0.1 -P %d -u %s", port, placeholderUser)
	case "mssql":
		return fmt.Sprintf("sqlserver://%s@127.0.0.1:%d", placeholderUser, port),
			fmt.Sprintf("sqlcmd -S 127.0.0.1,%d -U %s", port, placeholderUser)
	case "mongodb":
		return fmt.Sprintf("mongodb://127.0.0.1:%d", port),
			fmt.Sprintf("mongosh --host 127.0.0.1 --port %d", port)
	case "oracledb":
		return fmt.Sprintf("%s@127.0.0.1:%d", placeholderUser, port),
			fmt.Sprintf("sqlplus %s@127.0.0.1:%d", placeholderUser, port)
	case "redis":
		return fmt.Sprintf("redis://127.0.0.1:%d", port),
			fmt.Sprintf("redis-cli -h 127.0.0.1 -p %d", port)
	case "ssh":
		return "", fmt.Sprintf("ssh -p %d -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@127.0.0.1", port, placeholderUser)
	case "kubernetes":
		// kubectl reaches the cluster through the session kubeconfig rather than a port, and which
		// flags that needs depends on the other accounts, so the example is built in
		// RenderInstructions where every account is known.
		return "", ""
	case "windows":
		return "", fmt.Sprintf("connect an RDP client to 127.0.0.1:%d", port)
	}
	return "", ""
}

// RenderInstructions produces the markdown document handed to the agent.
func RenderInstructions(accounts []LiveAccount) string {
	var out strings.Builder

	out.WriteString("# Infisical PAM: live privileged access\n\n")

	fmt.Fprintf(&out, "%s available through local proxies on this machine. Connect to\n", pluralizeAccounts(len(accounts)))
	out.WriteString("127.0.0.1 on the ports below. Any username and password will work: the real\n")
	out.WriteString("credentials are injected by the Infisical gateway and are never exposed to you.\n")
	out.WriteString("Every command you run through these proxies is recorded and attributed to you.\n\n")

	// Without this, an agent tends to read the sample command as the only sanctioned way in, and
	// reports the account unusable when that particular binary happens to be missing.
	out.WriteString("These are ordinary network endpoints. Reach them with whatever client or library\n")
	out.WriteString("suits the task: a command-line tool, a driver imported from a script you write, or\n")
	out.WriteString("anything else already installed. The sample commands below are one option, not a\n")
	out.WriteString("requirement. If a sample command is unavailable, connect from code with a standard\n")
	out.WriteString("driver instead of treating the account as unreachable.\n\n")

	for _, account := range accounts {
		note, example := kubernetesGuidance(account)
		if example == "" {
			example = account.Example
		}

		fmt.Fprintf(&out, "## %s (%s)\n", flatten(account.Path), account.TypeLabel)
		if account.AwaitingApproval {
			out.WriteString("- STATUS: NEEDS APPROVAL. This account needs a human to approve access, and is not usable\n")
			out.WriteString("  yet. Your first connection attempt raises an access request automatically, and that\n")
			out.WriteString("  attempt fails. The port below stays reserved throughout. Once a reviewer approves, the\n")
			out.WriteString("  next attempt works, with nothing to restart or re-run, so retry periodically rather\n")
			out.WriteString("  than treating the account as unreachable. Only reach for this account if you actually\n")
			out.WriteString("  need it: the attempt puts a request in front of a person.\n")
		}
		fmt.Fprintf(&out, "- Host: 127.0.0.1, port %d\n", account.Port)
		if account.ConnectionString != "" {
			fmt.Fprintf(&out, "- Connection string: %s\n", account.ConnectionString)
		}
		if example != "" {
			fmt.Fprintf(&out, "- Sample command (one option among many): %s\n", example)
		}
		if note != "" {
			fmt.Fprintf(&out, "- %s\n", note)
		}
		out.WriteString("\n")
	}

	out.WriteString("## Rules\n")
	out.WriteString("- Use these proxies for the databases and hosts described above. Do not connect to\n")
	out.WriteString("  other hosts, and do not use credentials from any other source.\n")
	out.WriteString("- Any client or library is fine. The restriction is which hosts you connect to,\n")
	out.WriteString("  not how you connect to them.\n")
	out.WriteString("- These proxies stop working when the Infisical session ends.\n")

	// Said explicitly because the failure mode we care about is an agent deciding a blocked account
	// justifies finding its own way in.
	if anyAwaitingApproval(accounts) {
		out.WriteString("- An account marked NEEDS APPROVAL is blocked on a human, not on you. Do not look for\n")
		out.WriteString("  another route to it and do not use credentials from any other source. If you cannot\n")
		out.WriteString("  make progress without it, say so and stop.\n")
	}

	// Applies to accounts that are granted right now too: a grant is time-bounded, and one running out
	// mid-run looks exactly like an account that broke unless the agent has been told otherwise.
	if anyRequiresApproval(accounts) {
		out.WriteString("- Access to some of these accounts is granted for a limited window. An account that\n")
		out.WriteString("  worked earlier can start refusing connections once its window closes. A new approval\n")
		out.WriteString("  request is raised for you automatically on the next attempt, and the port does not\n")
		out.WriteString("  change. Treat it as a wait, not as a broken account.\n")
	}

	return out.String()
}

func anyAwaitingApproval(accounts []LiveAccount) bool {
	for _, account := range accounts {
		if account.AwaitingApproval {
			return true
		}
	}
	return false
}

func anyRequiresApproval(accounts []LiveAccount) bool {
	for _, account := range accounts {
		if account.RequiresApproval {
			return true
		}
	}
	return false
}

// kubernetesGuidance explains how kubectl reaches this particular cluster, and returns the sample
// command that actually goes there.
//
// Only one context in the session kubeconfig can be the current one, so with more than one
// kubernetes account a bare `kubectl get pods` reaches whichever cluster holds it. Every other
// cluster has to be named with --context, or privileged commands land on the wrong cluster.
func kubernetesGuidance(account LiveAccount) (note, example string) {
	if account.Type != "kubernetes" || account.KubeContext == "" {
		return "", ""
	}

	if account.IsCurrentKubeContext {
		return fmt.Sprintf(
				"KUBECONFIG is already set for this session and this cluster is its current context (%s), so plain kubectl commands reach it.",
				account.KubeContext),
			"kubectl get pods"
	}

	return fmt.Sprintf(
			"KUBECONFIG is already set for this session, but this cluster is NOT the current context: pass --context %s on every kubectl command meant for it, or it will run against a different cluster.",
			account.KubeContext),
		fmt.Sprintf("kubectl --context %s get pods", account.KubeContext)
}

func pluralizeAccounts(count int) string {
	if count == 1 {
		return "One privileged account is"
	}
	return fmt.Sprintf("%d privileged accounts are", count)
}

// flatten reduces text that came from the account record to a single line. Markdown structure only
// exists at the start of a line, so nothing arriving from outside can forge a heading or a bullet in
// a document the agent reads as its instructions.
func flatten(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
