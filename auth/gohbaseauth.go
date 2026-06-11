// Package gohbaseauth implements Kerberos SASL GSSAPI authentication
// for both ZooKeeper and HBase RegionServer connections.
package gohbaseauth

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

// ---------------------------------------------------------------------------
// HBase SASL wire constants
// ---------------------------------------------------------------------------

const (
	hbaseMagic       = "HBas"
	hbaseVersion     = byte(0x00)
	maxSASLTokenSize = 10 * 1024 * 1024
	qopReadTimeout   = 500 * time.Millisecond

	// HBaseAuthSimple SIMPLE auth preamble byte.
	HBaseAuthSimple byte = 0x50
	// HBaseAuthSASL SASL auth preamble byte.
	HBaseAuthSASL byte = 0x51
)

// ---------------------------------------------------------------------------
// Kerberos client factory
// ---------------------------------------------------------------------------

// Config holds Kerberos authentication configuration.
type Config struct {
	AuthMode    int8
	Principal   string
	Password    string
	ConfigPath  string
	KeytabPath  string
	DisableFAST bool
}

// NewClient creates a gokrb5 Client from config and logs it in.
func NewClient(cfg Config) (*client.Client, error) {
	krb5conf, err := config.Load(cfg.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("load krb5.conf %q: %w", cfg.ConfigPath, err)
	}

	principalName, realm, err := splitPrincipal(cfg.Principal)
	if err != nil {
		return nil, err
	}

	clientOpts := []func(*client.Settings){}
	if cfg.DisableFAST {
		clientOpts = append(clientOpts, client.DisablePAFXFAST(true))
	}

	var krbClient *client.Client
	switch cfg.AuthMode {
	case 1: // password
		krbClient = client.NewWithPassword(principalName, realm, cfg.Password, krb5conf, clientOpts...)
	case 2: // keytab
		kt, err := keytab.Load(cfg.KeytabPath)
		if err != nil {
			return nil, fmt.Errorf("load keytab %q: %w", cfg.KeytabPath, err)
		}
		krbClient = client.NewWithKeytab(principalName, realm, kt, krb5conf, clientOpts...)
	default:
		return nil, fmt.Errorf("unsupported auth mode %d", cfg.AuthMode)
	}

	if err := krbClient.Login(); err != nil {
		return nil, fmt.Errorf("kdc login for %q: %w", cfg.Principal, err)
	}
	return krbClient, nil
}

// BuildSPN builds a Kerberos Service Principal Name.
// If service is empty, defaults to "hbase".
func BuildSPN(host, service string) string {
	if service == "" {
		service = "hbase"
	}
	return service + "/" + host
}

func splitPrincipal(principal string) (name, realm string, err error) {
	principal = strings.TrimSpace(principal)
	name, realm, ok := strings.Cut(principal, "@")
	if !ok || name == "" || realm == "" {
		return "", "", fmt.Errorf("principal must be in primary[/instance]@REALM format: %q", principal)
	}
	return strings.TrimSpace(name), strings.TrimSpace(realm), nil
}

// ---------------------------------------------------------------------------
// GSSAPI token generation
// ---------------------------------------------------------------------------

// GenerateAPREQToken generates a GSSAPI KRB5 AP-REQ token for the given SPN.
func GenerateAPREQToken(krbClient *client.Client, spn string) ([]byte, error) {
	tkt, sessionKey, err := krbClient.GetServiceTicket(spn)
	if err != nil {
		return nil, fmt.Errorf("get service ticket for %q: %w", spn, err)
	}

	krb5Token, err := spnego.NewKRB5TokenAPREQ(krbClient, tkt, sessionKey, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("build AP-REQ token: %w", err)
	}

	token, err := krb5Token.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal AP-REQ token: %w", err)
	}
	return token, nil
}

// GenerateAPREQTokenForSPN generates an AP-REQ token for a full service
// principal such as "zookeeper/host@REALM".
func GenerateAPREQTokenForSPN(krbClient *client.Client, spn string) ([]byte, error) {
	if strings.TrimSpace(spn) == "" {
		return nil, fmt.Errorf("SPN must not be empty")
	}
	pn, _ := types.ParseSPNString(spn)
	ticketSPN := pn.PrincipalNameString()
	token, err := GenerateAPREQToken(krbClient, ticketSPN)
	if err != nil {
		return nil, fmt.Errorf("get service ticket for %q (requested as %q): %w", spn, ticketSPN, err)
	}
	return token, nil
}

// ---------------------------------------------------------------------------
// RegionServer SASL handshake (used by RegionDialer)
// ---------------------------------------------------------------------------

// PerformRegionServerSASLHandshake writes the SASL preamble and AP-REQ token
// to the RegionServer connection, reads and verifies the AP-REP response.
func PerformRegionServerSASLHandshake(_ context.Context, conn net.Conn, krbClient *client.Client, spn string) error {
	tkt, sessionKey, err := krbClient.GetServiceTicket(spn)
	if err != nil {
		return fmt.Errorf("get service ticket for %q: %w", spn, err)
	}

	krb5Token, err := spnego.NewKRB5TokenAPREQ(krbClient, tkt, sessionKey, nil, nil)
	if err != nil {
		return fmt.Errorf("build AP-REQ: %w", err)
	}
	initToken, err := krb5Token.Marshal()
	if err != nil {
		return fmt.Errorf("marshal AP-REQ: %w", err)
	}

	// Write SASL preamble: HBas + version + auth type
	preamble := []byte{hbaseMagic[0], hbaseMagic[1], hbaseMagic[2], hbaseMagic[3], hbaseVersion, HBaseAuthSASL}
	if _, err := conn.Write(preamble); err != nil {
		return fmt.Errorf("write SASL preamble: %w", err)
	}
	// Write token length + token
	if err := writeLengthPrefixed(conn, initToken); err != nil {
		return fmt.Errorf("write AP-REQ: %w", err)
	}

	// Read response
	respToken, err := readLengthPrefixed(conn)
	if err != nil {
		return fmt.Errorf("read AP-REP: %w", err)
	}
	if len(respToken) == 0 {
		return negotiateQoP(conn, sessionKey)
	}

	var respKRB5 spnego.KRB5Token
	if err := respKRB5.Unmarshal(respToken); err != nil {
		return fmt.Errorf("unmarshal AP-REP: %w", err)
	}
	if respKRB5.IsKRBError() {
		return fmt.Errorf("server returned KRBError: code=%d text=%s",
			respKRB5.KRBError.ErrorCode, respKRB5.KRBError.EText)
	}
	if !respKRB5.IsAPRep() {
		return fmt.Errorf("unexpected response type (expected AP-REP)")
	}
	if ok, status := respKRB5.Verify(); !ok {
		return fmt.Errorf("AP-REP verify failed: %s", status)
	}

	return negotiateQoP(conn, sessionKey)
}

// ---------------------------------------------------------------------------
// ZooKeeper SASL token generation
// ---------------------------------------------------------------------------

// ZKGSSAPIToken generates a GSSAPI token suitable for ZK SASL auth.
// Returns the token bytes and the service principal used.
func ZKGSSAPIToken(krbClient *client.Client, zkHost string) ([]byte, error) {
	spn := BuildSPN(zkHost, "zookeeper")
	return GenerateAPREQToken(krbClient, spn)
}

// ---------------------------------------------------------------------------
// wire helpers
// ---------------------------------------------------------------------------

func writeLengthPrefixed(conn net.Conn, data []byte) error {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(data)))
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(data)
	return err
}

func readLengthPrefixed(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header)
	if length == 0 {
		return nil, nil
	}
	if length > maxSASLTokenSize {
		return nil, fmt.Errorf("token too large: %d", length)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}
	return data, nil
}

func negotiateQoP(conn net.Conn, sessionKey types.EncryptionKey) error {
	if err := conn.SetReadDeadline(time.Now().Add(qopReadTimeout)); err != nil {
		return fmt.Errorf("set QoP read deadline: %w", err)
	}
	defer conn.SetReadDeadline(time.Time{})

	token, err := readLengthPrefixed(conn)
	if err != nil || len(token) == 0 {
		return nil
	}
	return respondQoP(conn, token, sessionKey)
}

func respondQoP(conn net.Conn, token []byte, sessionKey types.EncryptionKey) error {
	var challenge gssapi.WrapToken
	if err := challenge.Unmarshal(token, true); err != nil {
		return fmt.Errorf("unmarshal RegionServer QoP wrap token: %w", err)
	}
	ok, err := challenge.Verify(sessionKey, keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil {
		return fmt.Errorf("verify RegionServer QoP wrap token: %w", err)
	}
	if !ok {
		return fmt.Errorf("verify RegionServer QoP wrap token: checksum mismatch")
	}
	if len(challenge.Payload) < 4 {
		return fmt.Errorf("RegionServer QoP payload too short: %d bytes", len(challenge.Payload))
	}
	if challenge.Payload[0]&0x01 == 0 {
		return fmt.Errorf("RegionServer does not allow auth QoP: mask=0x%02x", challenge.Payload[0])
	}

	responsePayload := []byte{0x01, challenge.Payload[1], challenge.Payload[2], challenge.Payload[3]}
	response, err := gssapi.NewInitiatorWrapToken(responsePayload, sessionKey)
	if err != nil {
		return fmt.Errorf("build RegionServer QoP response token: %w", err)
	}
	responseToken, err := response.Marshal()
	if err != nil {
		return fmt.Errorf("marshal RegionServer QoP response token: %w", err)
	}
	if err := writeLengthPrefixed(conn, responseToken); err != nil {
		return fmt.Errorf("write RegionServer QoP response token: %w", err)
	}
	return nil
}
