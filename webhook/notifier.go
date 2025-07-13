package webhook

import (
	domain "assignment"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/avast/retry-go"
	"github.com/google/uuid"
)

var _ domain.NonMatchingIPNotifier = &Notifier{}

type NotifierCfg struct {
	Retries uint
	Timeout time.Duration
	URL     string
}

type Notifier struct {
	cli http.Client
	cfg NotifierCfg
}

func NewNotifier(cfg NotifierCfg) *Notifier {
	return &Notifier{
		cfg: cfg,
		cli: http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

type requestBody struct {
	PrevIP    net.IP    `json:"previous_ip"`
	CurrentIP net.IP    `json:"current_ip"`
	UserID    uuid.UUID `json:"user_id"`
}

func (n *Notifier) Notify(ctx context.Context, dto domain.IPNotificationDTO) error {
	body := requestBody{
		PrevIP:    dto.PrevIP,
		CurrentIP: dto.CurrentIP,
		UserID:    dto.UserID,
	}

	buf := bytes.NewBuffer(nil)
	json.NewEncoder(buf).Encode(body)

	req, err := http.NewRequestWithContext(ctx, "GET", n.cfg.URL, buf)
	if err != nil {
		return fmt.Errorf("could not create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	return retry.Do(func() error {
		resp, err := n.cli.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != 200 {
			return errors.New("status code does not equal 200")
		}

		return nil
	}, retry.Attempts(n.cfg.Retries))
}
