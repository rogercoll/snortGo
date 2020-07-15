package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/rogercoll/snort"
	"github.com/spf13/cobra"
)

var rootCmd *cobra.Command

var iface, file string

func init() {
	rootCmd = &cobra.Command{
		Use:   "snort",
		Short: "Scan any packet that enters/exits any network interface",
		Long: `A longer description that spans multiple lines and likely contains
	examples and usage of using your application. For example:
	Cobra is a CLI library for Go that empowers applications.
	This application is a tool to generate the needed files
	to quickly create a Cobra application.`,

		Run: func(cmd *cobra.Command, args []string) {
			iface, err := rootCmd.Flags().GetString("iface")
			if err != nil {
				log.Fatal(err)
			}
			file, err := rootCmd.Flags().GetString("f")
			if err != nil {
				log.Fatal(err)
			}
			err = snort.Watch(iface, file)
			if err != nil {
				log.Fatal(err)
			}
		},
	}
}

func Execute() {
	rootCmd.Flags().StringVar(&iface, "iface", "eth0", "Network interface to scan")
	rootCmd.Flags().StringVar(&file, "f", "/etc/snort.conf", "Rules file")
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
