package gatewayv2

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
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

	statement, err := alterPasswordStatement(params)
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, err.Error())
		return
	}

	target, _ := r.Context().Value(rpcTargetContextKey{}).(rpcTarget)

	if err := runWithContextTimeoutMessage(ctx, func() error {
		return doSQLRotate(ctx, target.host, target.port, params, statement)
	}, "the password change timed out before the target answered, and may still have been applied"); err != nil {
		msg := redactProbeSecrets(err.Error(), params.Password, params.NewPassword)
		writeRPCErrorWithKind(w, http.StatusBadGateway, msg, string(classifyTestConnFailure(err)))
		return
	}
	writeRPCJSON(w, http.StatusOK, testConnectionResponse{Result: testConnectionResult{Ok: true}})
}

func doSQLRotate(ctx context.Context, host string, port int, params sqlRotateParams, statement string) error {
	if err := dialTarget(ctx, host, port); err != nil {
		return connectFailure(err)
	}

	db, err := openSQLTestDB(host, port, params.sqlTestParams)
	if err != nil {
		return connectFailure(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, statement); err != nil {
		return sqlAuthFailure(params.Dialect, err)
	}
	return nil
}

func alterPasswordStatement(params sqlRotateParams) (string, error) {
	if params.Dialect != "oracle" {
		return "", fmt.Errorf("credential rotation over this transport is not supported for dialect %q", params.Dialect)
	}

	for label, v := range map[string]string{"username": params.TargetUsername, "password": params.NewPassword} {
		if strings.Contains(v, `"`) {
			return "", fmt.Errorf("oracle %s cannot contain a double quote", label)
		}
	}

	stmt := fmt.Sprintf(`ALTER USER "%s" IDENTIFIED BY "%s"`, params.TargetUsername, params.NewPassword)

	if params.TargetUsername == params.Username && params.Password != "" {
		if strings.Contains(params.Password, `"`) {
			return "", fmt.Errorf("oracle password cannot contain a double quote")
		}
		stmt += fmt.Sprintf(` REPLACE "%s"`, params.Password)
	}
	return stmt, nil
}
