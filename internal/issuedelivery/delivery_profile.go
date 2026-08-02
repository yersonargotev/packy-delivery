package issuedelivery

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/yersonargotev/packy-delivery/internal/deliveryevidence"
)

const deliveryProfilePrefix = "delivery:"

var deliveryProfileLabels = map[deliveryevidence.DeliveryRiskProfile]DeliveryProfileLabel{
	deliveryevidence.RiskLow:      "delivery:low-risk",
	deliveryevidence.RiskStandard: "delivery:standard",
	deliveryevidence.RiskHigh:     "delivery:high-risk",
}

type DeliveryProfileBinding struct {
	AuthorityLabel string                               `json:"authority_label"`
	Profile        deliveryevidence.DeliveryRiskProfile `json:"profile"`
}

func expectedDeliveryProfileLabel(profile deliveryevidence.DeliveryRiskProfile) (string, error) {
	label, ok := deliveryProfileLabels[profile]
	if !ok {
		return "", errors.New("declared delivery risk profile is invalid")
	}
	return string(label), nil
}

func (label DeliveryProfileLabel) Valid() bool {
	for _, expected := range deliveryProfileLabels {
		if label == expected {
			return true
		}
	}
	return false
}

func normalizedDeliveryProfileLabels(labels []string) []string {
	seen := make(map[string]bool)
	for _, label := range labels {
		label = strings.ToLower(strings.TrimSpace(label))
		if strings.HasPrefix(label, deliveryProfilePrefix) && !seen[label] {
			seen[label] = true
		}
	}
	profiles := make([]string, 0, len(seen))
	for label := range seen {
		profiles = append(profiles, label)
	}
	sort.Strings(profiles)
	return profiles
}

func NormalizeDeliveryProfileLabels(labels []string) []string {
	return normalizedDeliveryProfileLabels(labels)
}

func qualifyDeliveryProfile(
	labels []string,
	declared deliveryevidence.DeliveryRiskProfile,
) (*DeliveryProfileBinding, error) {
	profiles := normalizedDeliveryProfileLabels(labels)
	if len(profiles) != 1 {
		return nil, fmt.Errorf("approved delivery authority requires exactly one delivery profile; observed %d", len(profiles))
	}
	expected, err := expectedDeliveryProfileLabel(declared)
	if err != nil {
		return nil, err
	}
	if profiles[0] != expected {
		return nil, fmt.Errorf("authority delivery profile %q does not match declared risk profile %q", profiles[0], declared)
	}
	return &DeliveryProfileBinding{AuthorityLabel: expected, Profile: declared}, nil
}

func qualifiedRiskProfile(
	record runRecord,
	fallback deliveryevidence.DeliveryRiskProfile,
) deliveryevidence.DeliveryRiskProfile {
	if record.DeliveryProfile != nil {
		return record.DeliveryProfile.Profile
	}
	return fallback
}
