package gatewayv2

import (
	"bufio"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	maxSQLRequestBytes = 64 * 1024
	sqlDefaultTimeout  = 30 * time.Second
	sqlMaxTimeout      = 120 * time.Second
	sqlReqDeadline     = 180 * time.Second
)

func serveSQLOverTLS(ctx context.Context, conn *tls.Conn, reader *bufio.Reader, forwardConfig *ForwardConfig) error {
	return serveRPCOverTLS(ctx, conn, reader, forwardConfig, sqlMux(), sqlReqDeadline, "sql")
}

var sqlMux = sync.OnceValue(func() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/rotate-credential", handleSQLRotateCredential)
	return mux
})

type sqlRotateParams struct {
	sqlTestParams
	TargetUsername string `json:"targetUsername"`
	NewPassword    string `json:"newPassword"`
}

type sqlRotateEnvelope struct {
	TimeoutMs int `json:"timeoutMs"`
}

func handleSQLRotateCredential(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRPCError(w, http.StatusMethodNotAllowed, "Only POST is supported")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxSQLRequestBytes))
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var env sqlRotateEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		writeRPCError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	timeout := sqlDefaultTimeout
	if env.TimeoutMs > 0 {
		if int64(env.TimeoutMs) > int64(sqlMaxTimeout/time.Millisecond) {
			timeout = sqlMaxTimeout
		} else {
			timeout = time.Duration(env.TimeoutMs) * time.Millisecond
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	var params sqlRotateParams
	if err := json.Unmarshal(body, &params); err != nil {
		writeRPCError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if params.TargetUsername == "" || params.NewPassword == "" {
		writeRPCError(w, http.StatusBadRequest, "targetUsername and newPassword are required")
		return
	}

	if err := validateOracleRotateParams(params); err != nil {
		writeRPCError(w, http.StatusBadRequest, err.Error())
		return
	}

	target, _ := r.Context().Value(rpcTargetContextKey{}).(rpcTarget)

	if err := runWithContextTimeoutMessage(ctx, func() error {
		return doSQLRotate(ctx, target.host, target.port, params)
	}, "the password change timed out before the target answered, and may still have been applied"); err != nil {
		msg := redactProbeSecrets(err.Error(), params.Password, params.NewPassword)
		writeRPCErrorWithKind(w, http.StatusBadGateway, msg, string(classifyTestConnFailure(err)))
		return
	}
	writeRPCJSON(w, http.StatusOK, testConnectionResponse{Result: testConnectionResult{Ok: true}})
}

func doSQLRotate(ctx context.Context, host string, port int, params sqlRotateParams) error {
	if err := dialTarget(ctx, host, port); err != nil {
		return connectFailure(err)
	}

	db, err := openSQLTestDB(host, port, params.sqlTestParams)
	if err != nil {
		return connectFailure(err)
	}
	defer db.Close()

	targetUsername, exact, err := resolveOracleUsername(ctx, db, params.TargetUsername)
	if err != nil {
		return err
	}
	sessionUsername, err := sessionOracleUsername(ctx, db)
	if err != nil {
		return sqlAuthFailure(params.Dialect, err)
	}

	statement, err := alterPasswordStatement(params, targetUsername, sessionUsername, exact)
	if err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, statement); err != nil {
		return sqlAuthFailure(params.Dialect, err)
	}
	return nil
}

func validateOracleRotateParams(params sqlRotateParams) error {
	if params.Dialect != "oracle" {
		return fmt.Errorf("credential rotation over this transport is not supported for dialect %q", params.Dialect)
	}
	for label, v := range map[string]string{"username": params.TargetUsername, "password": params.NewPassword, "current password": params.Password} {
		if strings.Contains(v, `"`) {
			return fmt.Errorf("oracle %s cannot contain a double quote", label)
		}
	}
	return nil
}

func alterPasswordStatement(params sqlRotateParams, targetUsername, sessionUsername string, exact bool) (string, error) {
	if err := validateOracleRotateParams(params); err != nil {
		return "", err
	}
	if strings.Contains(targetUsername, `"`) {
		return "", fmt.Errorf("oracle username cannot contain a double quote")
	}

	stmt := fmt.Sprintf(`ALTER USER "%s" IDENTIFIED BY "%s"`, targetUsername, params.NewPassword)

	sameAccount := targetUsername == sessionUsername
	if !exact {
		sameAccount = strings.EqualFold(targetUsername, sessionUsername)
	}
	if sameAccount && params.Password != "" {
		if strings.Contains(params.Password, `"`) {
			return "", fmt.Errorf("oracle password cannot contain a double quote")
		}
		stmt += fmt.Sprintf(` REPLACE "%s"`, params.Password)
	}
	return stmt, nil
}

func resolveOracleUsername(ctx context.Context, db *sql.DB, name string) (resolved string, exact bool, err error) {
	rows, qerr := db.QueryContext(ctx, `SELECT username FROM all_users WHERE UPPER(username) = UPPER(:1)`, name)
	if qerr != nil {
		log.Warn().Err(qerr).Str("username", name).Msg("oracle: could not look up the stored username, using it as provided")
		return name, false, nil
	}
	defer rows.Close()

	var matches []string
	for rows.Next() {
		var found string
		if serr := rows.Scan(&found); serr != nil {
			log.Warn().Err(serr).Str("username", name).Msg("oracle: could not read the username lookup result, using it as provided")
			return name, false, nil
		}
		if found == name {
			return name, true, nil
		}
		matches = append(matches, found)
	}
	if rerr := rows.Err(); rerr != nil {
		log.Warn().Err(rerr).Str("username", name).Msg("oracle: username lookup did not complete, using it as provided")
		return name, false, nil
	}

	switch len(matches) {
	case 0:
		return "", false, fmt.Errorf("oracle user %q does not exist", name)
	case 1:
		return matches[0], true, nil
	default:
		return "", false, fmt.Errorf("%q matches more than one Oracle user (%s); enter it exactly as Oracle stores it", name, strings.Join(matches, ", "))
	}
}

func sessionOracleUsername(ctx context.Context, db *sql.DB) (string, error) {
	var user string
	if err := db.QueryRowContext(ctx, `SELECT USER FROM DUAL`).Scan(&user); err != nil {
		return "", err
	}
	return user, nil
}
