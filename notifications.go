package domain

import (
	"context"
	"net"

	"github.com/google/uuid"
)

type IPNotificationDTO struct {
	PrevIP, CurrentIP net.IP
	UserID            uuid.UUID
}

type NonMatchingIPNotifier interface {
	Notify(ctx context.Context, dto IPNotificationDTO) error
}
