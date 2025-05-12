package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/datadog/grimoire/pkg/grimoire/detonators"
	"github.com/datadog/grimoire/pkg/grimoire/logs"
	utils "github.com/datadog/grimoire/pkg/grimoire/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type ShellCommand struct {
	CommandToRun string
	ScriptToRun  string
}

func NewShellCommand() *cobra.Command {
	var commandToRun string
	var scriptToRun string

	shellCmd := &cobra.Command{
		Use:          "shell",
		SilenceUsage: true,
		Example:      "Run an interactive shell. Grimoire will inject a unique identifier to your HTTP user agent when using the AWS CLI.",
		RunE: func(cmd *cobra.Command, args []string) error {
			command := ShellCommand{
				CommandToRun: commandToRun,
				ScriptToRun:  scriptToRun,
			}
			if err := command.Validate(); err != nil {
				return err
			}
			if err := ValidateFlags(); err != nil {
				return err
			}
			return command.Do()
		},
	}

	initLookupFlags(shellCmd)
	shellCmd.Flags().StringVarP(&commandToRun, "command", "c", "", "Command to execute in the shell (instead of running an interactive shell)")
	shellCmd.Flags().StringVarP(&scriptToRun, "script", "", "", "Path to a script to execute in the shell (instead of running an interactive shell)")

	return shellCmd
}

func (m *ShellCommand) Validate() error {
	if m.CommandToRun != "" && m.ScriptToRun != "" {
		return fmt.Errorf("only one of 'command' or 'script' can be specified")
	}
	return nil
}

func (m *ShellCommand) Do() error {
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigChan:
			cancel()
			close(sigChan)
			log.Info("Exiting Grimoire.")
			os.Exit(0)
		case <-ctx.Done():
		}
	}()

	detonationUuid := utils.NewDetonationID()

	if m.isInteractiveMode() {
		log.Info("Grimoire will now run your shell and automatically inject a unique identifier to your HTTP user agent when using the AWS CLI")
		log.Info("You can use the AWS CLI as usual. Press Ctrl+D or type 'exit' to return to Grimoire.")
		log.Info("When you exit the shell, Grimoire will look for the CloudTrail events that your commands have generated.")
		log.Info("Press ENTER to continue")
		if _, err := fmt.Scanln(); err != nil {
			return err
		}
	} else if m.CommandToRun != "" {
		log.Infof("Running detonation command: %s", m.CommandToRun)
	} else if m.ScriptToRun != "" {
		log.Infof("Running detonation script: %s", m.ScriptToRun)
	}

	startTime := time.Now()
	grimoireUserAgent := fmt.Sprintf("grimoire_%s", detonationUuid)
	commandToRun, args := m.getCommandToRun()
	log.Debugf("Running command: %s %v", commandToRun, args)
	cmd := exec.CommandContext(ctx, commandToRun, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Get the modified startup script for ZDOTDIR
	var zdotdir string
	if m.isInteractiveMode() {
		if startupScript, err := getModifiedShellStartupScript(); err == nil {
			zdotdir = filepath.Dir(startupScript)
			log.Debugf("Setting ZDOTDIR to %s", zdotdir)
		} else {
			log.Warnf("Failed to create modified startup script: %v", err)
		}
	}

	// Set up environment variables
	env := os.Environ()
	env = append(env,
		fmt.Sprintf("AWS_EXECUTION_ENV=%s", grimoireUserAgent),
		fmt.Sprintf("GRIMOIRE_DETONATION_ID=%s", detonationUuid), // generic environment variable to allow the user to pass it further if needed
	)
	if zdotdir != "" {
		env = append(env, fmt.Sprintf("ZDOTDIR=%s", zdotdir))
	}
	cmd.Env = env

	if err := cmd.Run(); err != nil && m.isExecutionError(err) {
		return fmt.Errorf("unable to run shell: %v", err)
	}
	endTime := time.Now()

	if m.isInteractiveMode() {
		log.Infof("Welcome back to Grimoire!")
	}

	// Create a DetonationInfo object
	detonationInfo := &detonators.DetonationInfo{
		DetonationID: detonationUuid,
		StartTime:    startTime,
		EndTime:      endTime,
	}

	// Process logs using the shared function
	return FindLogsForDetonation(context.Background(), detonationInfo, "shell", "", logs.UserAgentMatchTypePartial, nil)
}

func (m *ShellCommand) isExecutionError(err error) bool {
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		if _, ok := exitError.Sys().(syscall.WaitStatus); ok {
			return false
		}
	}

	return true
}

// getModifiedShellStartupScript copies the user's shell startup script to a temporary file,
// appends additional commands, and returns the path to the temporary file.
func getModifiedShellStartupScript() (string, error) {
	shell := os.Getenv("SHELL")
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %v", err)
	}

	// Determine which startup script to use based on the shell
	var startupScript string
	switch {
	case strings.Contains(shell, "zsh"):
		startupScript = filepath.Join(homeDir, ".zshrc")
	case strings.Contains(shell, "bash"):
		startupScript = filepath.Join(homeDir, ".bashrc")
		if _, err := os.Stat(startupScript); os.IsNotExist(err) {
			// Try .bash_profile if .bashrc doesn't exist
			startupScript = filepath.Join(homeDir, ".bash_profile")
		}
	default:
		return "", fmt.Errorf("unsupported shell: %s", shell)
	}

	// Check if the startup script exists
	if _, err := os.Stat(startupScript); os.IsNotExist(err) {
		return "", fmt.Errorf("startup script not found: %s", startupScript)
	}

	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "grimoire-shell-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary directory: %v", err)
	}

	// Create .zshrc in the temporary directory
	tmpFile := filepath.Join(tmpDir, ".zshrc")
	f, err := os.Create(tmpFile)
	if err != nil {
		os.RemoveAll(tmpDir) // Clean up the temp directory
		return "", fmt.Errorf("failed to create temporary file: %v", err)
	}
	defer f.Close()

	// Copy the original startup script
	originalFile, err := os.Open(startupScript)
	if err != nil {
		os.RemoveAll(tmpDir) // Clean up the temp directory
		return "", fmt.Errorf("failed to open startup script: %v", err)
	}
	defer originalFile.Close()

	if _, err := io.Copy(f, originalFile); err != nil {
		os.RemoveAll(tmpDir) // Clean up the temp directory
		return "", fmt.Errorf("failed to copy startup script: %v", err)
	}

	// Append additional commands
	additionalCommands := []string{
		"",
		"# Grimoire modifications",
		"export PS1='(grimoire) '$PS1",
		"",
	}

	if _, err := f.WriteString(strings.Join(additionalCommands, "\n")); err != nil {
		os.RemoveAll(tmpDir) // Clean up the temp directory
		return "", fmt.Errorf("failed to append additional commands: %v", err)
	}

	// Make the temporary file executable
	if err := os.Chmod(tmpFile, 0755); err != nil {
		os.RemoveAll(tmpDir) // Clean up the temp directory
		return "", fmt.Errorf("failed to make temporary file executable: %v", err)
	}

	log.Infof("Created modified shell startup script at %s", tmpFile)
	return tmpFile, nil
}

func (m *ShellCommand) getCommandToRun() (string, []string) {
	shell := os.Getenv("SHELL")
	if m.CommandToRun != "" {
		return shell, []string{"-c", m.CommandToRun}
	} else if m.ScriptToRun != "" {
		return shell, []string{"-x", m.ScriptToRun}
	} else {
		return shell, []string{"-i"}
	}
}

func (m *ShellCommand) isInteractiveMode() bool {
	return m.CommandToRun == "" && m.ScriptToRun == ""
}
