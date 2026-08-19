package agent

import (
	"fmt"
	"strings"

	pam "github.com/Infisical/infisical-merge/packages/pam/local"
)

// The username a client sends is irrelevant: every handler overwrites it with the real injected
// credential before the packet reaches the target. We therefore render a fixed placeholder rather
// than pretending to know the real value, which would require creating a session just to print a
// banner.
const placeholderUser = "pam"

// placeholderDatabase stands in for the database the account is configured with, which is likewise
// not known until a session exists.
//
// This is safe only because the handler forces the account's database into the handshake, making
// whatever the client asked for moot. MongoDB is the exception: it forwards the database the client
// names, so naming one here would send an agent to a database that is not the account's. See
// databaseFor.
//
// Named after the placeholder user rather than after any real database, so that a reader who has not
// realised it is ignored cannot mistake it for the name of one.
const placeholderDatabase = placeholderUser

// databaseFor returns the database to render for an account type: the placeholder for every type
// whose handler overrides it, and nothing for MongoDB, which does not.
func databaseFor(accountType string) string {
	if accountType == "mongodb" {
		return ""
	}
	return placeholderDatabase
}

// LiveAccount is one running proxy, as described to the agent.
type LiveAccount struct {
	Path             string
	Type             string
	TypeLabel        string
	Host             string
	Port             int
	ConnectionString string
	Examples         []string
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

// connectionFor describes how to reach a port-based account, taken from the same table the
// `infisical pam access` banner is built from so that an agent and a human are told the same thing
// about the same account.
//
// Kubernetes has nothing here on purpose: kubectl reaches the cluster through the session kubeconfig
// rather than a port, and which flags that needs depends on the other accounts, so its example is
// built in RenderInstructions where every account is known.
func connectionFor(accountType string, port int) (connectionString string, examples []string) {
	if accountType == "windows" {
		return "", []string{fmt.Sprintf("connect an RDP client to 127.0.0.1:%d", port)}
	}

	display, ok := pam.ConnectionDisplayFor(accountType)
	if !ok {
		return "", nil
	}

	database := databaseFor(accountType)
	return display.Connection(placeholderUser, database, port),
		display.ConnectionExamples(placeholderUser, database, port)
}

// RenderInstructions produces the markdown document handed to the agent.
//
// requestApproval mirrors the run's own setting, because what the agent should do about an approval
// gate depends entirely on it: with requests enabled a gate is a wait, and without them it is the end
// of the account. Telling the agent to keep retrying in the second case would send it back to an
// account nothing is going to unblock.
func RenderInstructions(accounts []LiveAccount, requestApproval bool) string {
	var out strings.Builder

	out.WriteString("# Infisical PAM: live privileged access\n\n")

	fmt.Fprintf(&out, "%s available through local proxies on this machine. Connect to\n", pluralizeAccounts(len(accounts)))
	out.WriteString("127.0.0.1 on the ports below. Any username works, and so does any database name: the\n")
	out.WriteString("Infisical gateway replaces both with the account's real credentials and database,\n")
	out.WriteString("which are never exposed to you. The values in the samples below are placeholders, so\n")
	out.WriteString("there is nothing to look up. Where an account does not work that way, it says so\n")
	out.WriteString("under the account itself.\n\n")

	// An agent that hits an auth error reaches for a password by reflex, and for MySQL that is the one
	// thing guaranteed to keep it out: the proxy accepts any user but expects an empty password, so a
	// supplied one is checked and fails. Said as a rule rather than a MySQL footnote, because it holds
	// everywhere and the reflex needs heading off before it starts.
	out.WriteString("Send no password at all, and leave any password field empty. There is no password to\n")
	out.WriteString("find, and some of these accept a connection only when none is sent, so adding one is\n")
	out.WriteString("never the fix for a connection that was refused.\n\n")

	out.WriteString("Every command you run through these proxies is recorded and attributed to you.\n\n")

	// Without this, an agent tends to read the sample command as the only sanctioned way in, and
	// reports the account unusable when that particular binary happens to be missing.
	out.WriteString("These are ordinary network endpoints. Reach them with whatever client or library\n")
	out.WriteString("suits the task: a command-line tool, a driver imported from a script you write, or\n")
	out.WriteString("anything else already installed. The sample commands below are one option, not a\n")
	out.WriteString("requirement. If a sample command is unavailable, connect from code with a standard\n")
	out.WriteString("driver instead of treating the account as unreachable.\n\n")

	for _, account := range accounts {
		note, kubeExample := kubernetesGuidance(account)
		examples := account.Examples
		if kubeExample != "" {
			examples = []string{kubeExample}
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
		switch len(examples) {
		case 0:
		case 1:
			fmt.Fprintf(&out, "- Sample command (one option among many): %s\n", examples[0])
		default:
			out.WriteString("- Sample commands (one option among many):\n")
			for _, example := range examples {
				fmt.Fprintf(&out, "  - %s\n", example)
			}
		}
		// The database an account is scoped to is forced into the handshake for every type but this
		// one, so this is the only case where an agent has to choose correctly on its own.
		if account.Type == "mongodb" {
			out.WriteString("- No database is preselected. Run `show dbs` to see what this account reaches, then name\n")
			out.WriteString("  the database explicitly: connecting without one lands on an empty database called `test`.\n")
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
	// mid-run looks exactly like an account that broke unless the agent has been told otherwise. What
	// it should then do differs, so the two cases are worded separately rather than softened into one.
	if anyRequiresApproval(accounts) {
		out.WriteString("- Access to some of these accounts is granted for a limited window. An account that\n")
		out.WriteString("  worked earlier can start refusing connections once its window closes.\n")
		if requestApproval {
			out.WriteString("  A new approval request is raised for you automatically on the next attempt, and the\n")
			out.WriteString("  port does not change. Treat it as a wait, not as a broken account.\n")
		} else {
			// Saying "wait" here would be false: this run cannot raise the request that would end the
			// wait, so the honest instruction is to stop rather than to retry.
			out.WriteString("  This run cannot request a new approval, so that account is done for the rest of the\n")
			out.WriteString("  run. Do not keep retrying it and do not look for another route to it. Say what you\n")
			out.WriteString("  could not finish and stop.\n")
		}
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
