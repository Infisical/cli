package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/Infisical/infisical-merge/packages/ca"
	"github.com/rs/zerolog/log"
)

type Config struct {
	Port              int
	PollInterval      time.Duration
	CADir             string
	AllowedHosts      []string
	BlockUnknownHosts bool
}

type SecretWithProxyConfig struct {
	SecretKey   string      `json:"secretKey"`
	SecretValue string      `json:"secretValue"`
	ProxyConfig ProxyConfig `json:"proxyConfig"`
}

type ProxyConfig struct {
	Placeholder string      `json:"placeholder"`
	Rules       []ProxyRule `json:"rules"`
}

type FetchFunc func() ([]SecretWithProxyConfig, error)

type Broker struct {
	proxy  *Proxy
	config Config
	fetch  FetchFunc
}

func New(cfg Config, fetchFn FetchFunc) (*Broker, error) {
	certAuthority, err := ca.New(cfg.CADir)
	if err != nil {
		return nil, fmt.Errorf("initializing CA: %w", err)
	}

	entries := make([]ServiceEntry, 0)
	secrets, err := fetchFn()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to fetch initial proxy configs, starting with empty rules")
	} else {
		entries = toServiceEntries(secrets)
		log.Info().Int("count", len(entries)).Msg("Loaded proxy-enabled secrets")
	}

	rules := ParseRules(entries)
	proxy := NewProxy(certAuthority, rules, cfg.AllowedHosts, cfg.BlockUnknownHosts)

	return &Broker{
		proxy:  proxy,
		config: cfg,
		fetch:  fetchFn,
	}, nil
}

func (b *Broker) CACertPEM() []byte {
	return b.proxy.ca.CertPEM()
}

func (b *Broker) SetProposalFunc(fn ProposalFunc) {
	b.proxy.SetProposalFunc(fn)
}

func (b *Broker) Listen() error {
	addr := fmt.Sprintf(":%d", b.config.Port)
	return b.proxy.Listen(addr)
}

func (b *Broker) Serve(ctx context.Context) error {
	go b.pollLoop(ctx)
	return b.proxy.Serve()
}

func (b *Broker) Start(ctx context.Context) error {
	if err := b.Listen(); err != nil {
		return err
	}
	return b.Serve(ctx)
}

func (b *Broker) Port() int {
	addr := b.proxy.Addr()
	if addr == nil {
		return 0
	}
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		return tcpAddr.Port
	}
	return 0
}

func (b *Broker) Stop() error {
	return b.proxy.Close()
}

func (b *Broker) pollLoop(ctx context.Context) {
	ticker := time.NewTicker(b.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			secrets, err := b.fetch()
			if err != nil {
				log.Warn().Err(err).Msg("Poll failed, keeping last-known-good config")
				continue
			}
			entries := toServiceEntries(secrets)
			rules := ParseRules(entries)
			b.proxy.UpdateRules(rules)
			log.Debug().Int("rules", len(rules)).Msg("Updated proxy rules")
		}
	}
}

func toServiceEntries(secrets []SecretWithProxyConfig) []ServiceEntry {
	entries := make([]ServiceEntry, 0, len(secrets))
	for _, s := range secrets {
		var rules []ProxyRule
		if err := json.Unmarshal([]byte(rulesJSON(s.ProxyConfig.Rules)), &rules); err != nil {
			rules = s.ProxyConfig.Rules
		}
		entries = append(entries, ServiceEntry{
			SecretKey:   s.SecretKey,
			SecretValue: s.SecretValue,
			Placeholder: s.ProxyConfig.Placeholder,
			Rules:       s.ProxyConfig.Rules,
		})
	}
	return entries
}

func rulesJSON(rules []ProxyRule) string {
	b, _ := json.Marshal(rules)
	return string(b)
}
