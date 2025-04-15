package utils

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	log "github.com/sirupsen/logrus"
)

// GetCloudTrailEventFullName returns the full name of a CloudTrail event, e.g. sts:GetCallerIdentity
func GetCloudTrailEventFullName(event *map[string]interface{}) string {
	eventName := (*event)["eventName"].(string)
	eventSourceShort := strings.TrimSuffix((*event)["eventSource"].(string), ".amazonaws.com")
	return fmt.Sprintf("%s:%s", eventSourceShort, eventName) // e.g. "sts:GetCallerIdentity"
}

// GetAWSConfig returns a properly configured AWS config
func GetAWSConfig(ctx context.Context) (aws.Config, error) {
	return config.LoadDefaultConfig(ctx)
}

// EnsureAWSAuthenticated checks if the user is authenticated to AWS
func EnsureAWSAuthenticated(ctx context.Context, awsConfig aws.Config) error {
	log.Debug("Checking AWS authentication using sts:GetCallerIdentity")
	stsClient := sts.NewFromConfig(awsConfig)
	_, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	return nil
}
