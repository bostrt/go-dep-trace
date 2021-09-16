package cmd

import (
	"fmt"
	"github.com/bostrt/go-dep-trace/pkg/graph"
	"github.com/bostrt/go-dep-trace/pkg/print"
	"github.com/spf13/cobra"
	"os"
	log "github.com/sirupsen/logrus"

)

var verbose bool
var sourcePkg string
var targetPkg string
var goModDir string
var mainProg string
var dotOutputFile string
var prettyPrint bool

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "go-dep-trace",
	Args: cobra.ExactArgs(2),
	Short: "short",
	Long: `long`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		// Ensure Args are set and for existing files
		goModDir = args[0]
		mainProg = args[1]

		gf, err := os.Open(goModDir)
		defer gf.Close()
		if err != nil {
			return err
		}

		mf, err := os.Open(mainProg)
		defer mf.Close()
		if err != nil {
			return err
		}

		// TODO: Do better validation
		if sourcePkg == "" {
			return fmt.Errorf("--source-pkg flag not set")
		}

		if targetPkg == "" {
			return fmt.Errorf("--target-pkg flag not set")
		}

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		if verbose {
			log.SetLevel(log.DebugLevel)
		}

		g, err := graph.GetCallGraph(goModDir, mainProg, sourcePkg, targetPkg)

		if err != nil {
			fmt.Println(err)
			return
		}

		dotGraph := graph.ConvertToDot(g)
		os.WriteFile(dotOutputFile, []byte(dotGraph.String()), 0644)
		log.Info("DOT file written to test.gv")

		if (prettyPrint) {
			print.TreePrint(g)
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&sourcePkg, "source-pkg", "", "")
	rootCmd.PersistentFlags().StringVar(&targetPkg, "target-pkg", "", "")
	rootCmd.PersistentFlags().StringVar(&goModDir, "go-mod", "", "")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "")
	rootCmd.PersistentFlags().StringVarP(&dotOutputFile, "output", "o", "dep-trace.out", "")
	rootCmd.PersistentFlags().BoolVar(&prettyPrint, "pretty", false, "")
}
