package warp

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/curve25519"
)

const (
	apiBase         = "https://api.cloudflareclient.com/v0a2158"
	cfClientVersion = "a-6.11-2223"
	AccountJSON     = "/etc/slipgate/warp/account.json"
)

// WarpAccount holds all WARP registration data.
type WarpAccount struct {
	DeviceID   string   `json:"device_id"`
	Token      string   `json:"token"`
	PrivateKey string   `json:"private_key"` // base64 WireGuard private key
	PublicKey  string   `json:"public_key"`  // base64 WireGuard public key
	PeerKey    string   `json:"peer_key"`    // base64 peer (Cloudflare) public key
	Endpoint   string   `json:"endpoint"`    // peer endpoint (host:port)
	Addresses  []string `json:"addresses"`   // interface addresses (IPv4, IPv6)
	ClientID   string   `json:"client_id"`   // base64 client_id from WARP API
	Reserved   [3]byte  `json:"reserved"`    // decoded reserved bytes from client_id
}

// registerResponse is the JSON response from the WARP registration API.
type registerResponse struct {
	ID     string `json:"id"`
	Token  string `json:"token"`
	Config struct {
		ClientID string `json:"client_id"`
		Peers    []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				Host string `json:"host"`
				V4   string `json:"v4"`
			} `json:"endpoint"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

// generateWireGuardKeys generates a Curve25519 keypair for WireGuard.
// Returns base64-encoded private and public keys.
func generateWireGuardKeys() (privKeyB64, pubKeyB64 string, err error) {
	var privKey [32]byte
	if _, err := rand.Read(privKey[:]); err != nil {
		return "", "", fmt.Errorf("generate random key: %w", err)
	}

	// Clamp private key per Curve25519 spec
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64

	pubKey, err := curve25519.X25519(privKey[:], curve25519.Basepoint)
	if err != nil {
		return "", "", fmt.Errorf("derive public key: %w", err)
	}

	return base64.StdEncoding.EncodeToString(privKey[:]),
		base64.StdEncoding.EncodeToString(pubKey), nil
}

// registerWARP registers a new device with the Cloudflare WARP API.
func registerWARP() (*WarpAccount, error) {
	privKeyB64, pubKeyB64, err := generateWireGuardKeys()
	if err != nil {
		return nil, err
	}

	body := map[string]string{
		"key":           pubKeyB64,
		"install_id":    "",
		"fcm_token":     "",
		"tos":           time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"model":         "Linux",
		"serial_number": "",
	}
	bodyJSON, _ := json.Marshal(body)

	req, err := http.NewRequest("POST", apiBase+"/reg", bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("CF-Client-Version", cfClientVersion)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("WARP API request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("WARP API returned %d: %s", resp.StatusCode, string(respBody))
	}

	var reg registerResponse
	if err := json.Unmarshal(respBody, &reg); err != nil {
		return nil, fmt.Errorf("parse WARP response: %w", err)
	}

	if len(reg.Config.Peers) == 0 {
		return nil, fmt.Errorf("WARP API returned no peers")
	}

	account := &WarpAccount{
		DeviceID:   reg.ID,
		Token:      reg.Token,
		PrivateKey: privKeyB64,
		PublicKey:  pubKeyB64,
		PeerKey:    reg.Config.Peers[0].PublicKey,
		ClientID:   reg.Config.ClientID,
	}

	// Prefer host endpoint, fall back to v4
	endpoint := reg.Config.Peers[0].Endpoint.Host
	if endpoint == "" {
		endpoint = reg.Config.Peers[0].Endpoint.V4
	}
	account.Endpoint = endpoint

	// Collect addresses
	if v4 := reg.Config.Interface.Addresses.V4; v4 != "" {
		account.Addresses = append(account.Addresses, v4+"/32")
	}
	if v6 := reg.Config.Interface.Addresses.V6; v6 != "" {
		account.Addresses = append(account.Addresses, v6+"/128")
	}

	// Decode client_id to reserved bytes
	if reg.Config.ClientID != "" {
		decoded, err := base64.StdEncoding.DecodeString(reg.Config.ClientID)
		if err == nil && len(decoded) >= 3 {
			account.Reserved = [3]byte{decoded[0], decoded[1], decoded[2]}
		}
	}

	return account, nil
}

// SaveAccount writes the WARP account to disk.
func SaveAccount(account *WarpAccount) error {
	data, err := json.MarshalIndent(account, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(AccountJSON, data, 0600)
}

// LoadAccount reads the WARP account from disk.
func LoadAccount() (*WarpAccount, error) {
	data, err := os.ReadFile(AccountJSON)
	if err != nil {
		return nil, err
	}
	var account WarpAccount
	if err := json.Unmarshal(data, &account); err != nil {
		return nil, err
	}
	return &account, nil
}

// migrateFromWgcf reads existing wgcf files and creates a WarpAccount.
// This allows existing users to keep their WARP config without re-registering.
func migrateFromWgcf() (*WarpAccount, error) {
	profile, err := parseWgProfile(ProfileFile)
	if err != nil {
		return nil, fmt.Errorf("parse wgcf profile: %w", err)
	}

	account := &WarpAccount{
		PrivateKey: profile.privateKey,
		PeerKey:    profile.publicKey,
		Endpoint:   profile.endpoint,
		Addresses:  profile.addresses,
	}

	return account, nil
}
