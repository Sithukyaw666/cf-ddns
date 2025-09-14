package cmd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/cloudflare/cloudflare-go"
	"github.com/spf13/cobra"
)

var oldIP, recordType, newIPFlag string

func getEnvOrExit(key string) string {
	value := os.Getenv(key)
	if value == "" {
		slog.Error("Required environment variables not set", "key", key)
		os.Exit(1)
	}
	return value

}

func getPublicIP() (string, error) {
	slog.Info("Fetching public IP address from api.ipify.org...")
	resp, err := http.Get("https://api.ipify.org")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get public IP: status code %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(body))
	return ip, nil
}

var rootCmd = &cobra.Command{
	Use:   "cf-ddns",
	Short: "A tool to automatically update Cloudflare DNS records.",
	Long:  "cf-ddns automatically finds the Cloudflare DNS recors maching an old IP and updates them to the new IP.",
	Run: func(cmd *cobra.Command, args []string) {
		logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
		slog.SetDefault(logger)

		apiToken := getEnvOrExit("CLOUDFLARE_API_TOKEN")
		zoneID := getEnvOrExit("CLOUDFLARE_ZONE_ID")
		slog.Info("Successfully loaded configuration", "zone_id", zoneID, "api_token", apiToken)

		var finalNewIP string
		var err error

		if newIPFlag != "" {
			slog.Info("Using IP address provided by --new-ip flag")
			if net.ParseIP(newIPFlag) == nil {
				slog.Error("Invalid IP address provided via --new-ip flag", "ip_address", newIPFlag)
				os.Exit(1)
			}
			finalNewIP = newIPFlag
		} else {
			finalNewIP, err = getPublicIP()
			if err != nil {
				slog.Error("Faield to get public IP address", "error", err)
				os.Exit(1)
			}
		}

		slog.Info("Target IP address for update is", "ip_address", finalNewIP)

		if finalNewIP == oldIP {
			slog.Info("Target IP is the same as old IP. No update needed.")
			os.Exit(1)
		}

		slog.Info("Initializing Cloudflare API client...")
		cfAPI, err := cloudflare.NewWithAPIToken(apiToken)
		if err != nil {
			slog.Error("Failed to create cloudflare API client", "error", err)
			os.Exit(1)
		}

		slog.Info("Cloudflare API client initialized successfully.")

		slog.Info("Fetching DNS records...", "zone_id", zoneID)
		records, _, err := cfAPI.ListDNSRecords(context.Background(), cloudflare.ZoneIdentifier(zoneID), cloudflare.ListDNSRecordsParams{
			Type:    recordType,
			Content: oldIP,
		})
		if err != nil {
			slog.Error("Failed to fetch DNS records from cloudflare", "error", err)
			os.Exit(1)
		}
		slog.Info("Successfully fetched DNS records", "count", len(records))

		var updatedCount int
		slog.Info("Scanning records to find matches for update...", "old-ip", oldIP, "type", recordType)

		for _, record := range records {
			slog.Info("Found record to update", "name", record.Name, "type", recordType, "content", record.Content)
			params := cloudflare.UpdateDNSRecordParams{
				Content: finalNewIP,
				ID:      record.ID,
			}
			_, err := cfAPI.UpdateDNSRecord(context.Background(), cloudflare.ZoneIdentifier(zoneID), params)
			if err != nil {
				slog.Error("Failed to update DNS record", "name", record.Name, "error", err)
				continue
			}
			slog.Info("Successfully updated record", "name", record.Name, "new_ip", finalNewIP)
			updatedCount++

		}
		if updatedCount == 0 {
			slog.Info("No records matched the criteria. No updates performed.")
		} else {
			slog.Info("Update summary", "record_updated", updatedCount)
		}

		slog.Info("DNS update process finished.")
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
func init() {
	rootCmd.PersistentFlags().StringVar(&oldIP, "old-ip", "", "The old IP address to search for and replace (required)")
	rootCmd.PersistentFlags().StringVar(&recordType, "record-type", "A", "Record type to update (A or AAAA)")
	rootCmd.MarkPersistentFlagRequired("old-ip")

	rootCmd.PersistentFlags().StringVar(&newIPFlag, "new-ip", "", "Optionally: Manually specify the new IP address")
}
