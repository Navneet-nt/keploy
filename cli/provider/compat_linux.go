//go:build linux

package provider

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/moby/moby/pkg/parsers/kernel"
	"go.uber.org/zap"
)

const (
	// Minimum required kernel version for eBPF support
	MinKernelMajor = 5
	MinKernelMinor = 10
	MinKernelPatch = 0
	
	// Cgroup v2 mount path
	CgroupV2MountPath = "/sys/fs/cgroup/cgroup.controllers"
	
	// Error messages
	ErrKernelVersionFmt = "detected linux kernel version %s. Keploy requires linux kernel version %d.%d.%d or above. Please upgrade your kernel or docker version"
	ErrCgroupV2NotSupported = "cgroup v2 is not supported or enabled on this system. Keploy requires cgroup v2 for proper container isolation"
)

// KernelCompatibilityError represents a kernel compatibility error with structured information
type KernelCompatibilityError struct {
	CurrentVersion  string
	RequiredVersion string
	Message         string
}

func (e *KernelCompatibilityError) Error() string {
	return e.Message
}

// CgroupV2Error represents a cgroup v2 compatibility error
type CgroupV2Error struct {
	Message string
}

func (e *CgroupV2Error) Error() string {
	return e.Message
}

// isCompatible checks if the current Linux environment is compatible with Keploy requirements
func isCompatible(logger *zap.Logger) error {
	// Check kernel version compatibility
	if err := checkKernelCompatibility(logger); err != nil {
		return err
	}

	// Check cgroup v2 support
	if err := checkCgroupV2Support(logger); err != nil {
		return err
	}

	logger.Info("System compatibility check passed",
		zap.String("component", "keploy-compatibility"),
		zap.String("status", "compatible"))

	return nil
}

// checkKernelCompatibility verifies that the kernel version meets minimum requirements for eBPF
func checkKernelCompatibility(logger *zap.Logger) error {
	logger.Debug("Checking kernel version compatibility",
		zap.Int("required_major", MinKernelMajor),
		zap.Int("required_minor", MinKernelMinor),
		zap.Int("required_patch", MinKernelPatch))

	isValid := kernel.CheckKernelVersion(MinKernelMajor, MinKernelMinor, MinKernelPatch)
	if isValid {
		// Log successful validation with current version info
		if currentVersion, err := kernel.GetKernelVersion(); err == nil {
			logger.Debug("Kernel version check passed",
				zap.String("current_version", currentVersion.String()),
				zap.String("required_version", fmt.Sprintf("%d.%d.%d", MinKernelMajor, MinKernelMinor, MinKernelPatch)))
		}
		return nil
	}

	// Handle kernel version incompatibility
	currentVersion, err := kernel.GetKernelVersion()
	if err != nil {
		logger.Error("Failed to retrieve kernel version", 
			zap.Error(err),
			zap.String("context", "kernel compatibility check"))
		return fmt.Errorf("failed to retrieve kernel version: %w", err)
	}

	requiredVersionStr := fmt.Sprintf("%d.%d.%d", MinKernelMajor, MinKernelMinor, MinKernelPatch)
	errorMessage := fmt.Sprintf(ErrKernelVersionFmt, currentVersion.String(), MinKernelMajor, MinKernelMinor, MinKernelPatch)
	
	logger.Error("Kernel version compatibility check failed",
		zap.String("current_version", currentVersion.String()),
		zap.String("required_version", requiredVersionStr),
		zap.String("reason", "eBPF support requires kernel 5.10+"))

	return &KernelCompatibilityError{
		CurrentVersion:  currentVersion.String(),
		RequiredVersion: requiredVersionStr,
		Message:         errorMessage,
	}
}

// checkCgroupV2Support verifies that cgroup v2 is available and enabled
func checkCgroupV2Support(logger *zap.Logger) error {
	logger.Debug("Checking cgroup v2 support")

	// Check if cgroup v2 is mounted and available
	if !isCgroupV2Available() {
		logger.Error("Cgroup v2 compatibility check failed",
			zap.String("mount_path", CgroupV2MountPath),
			zap.String("reason", "cgroup v2 not available or not mounted"))
		
		return &CgroupV2Error{
			Message: ErrCgroupV2NotSupported,
		}
	}

	// Additional check: verify cgroup v2 controllers are available
	controllers, err := getCgroupV2Controllers()
	if err != nil {
		logger.Warn("Could not read cgroup v2 controllers", 
			zap.Error(err),
			zap.String("note", "continuing with basic cgroup v2 check"))
	} else {
		logger.Debug("Cgroup v2 controllers detected",
			zap.Strings("controllers", controllers))
	}

	logger.Debug("Cgroup v2 support check passed")
	return nil
}

// isCgroupV2Available checks if cgroup v2 is mounted and accessible
func isCgroupV2Available() bool {
	// Check if the cgroup v2 controller file exists
	if _, err := os.Stat(CgroupV2MountPath); err != nil {
		return false
	}

	// Additional check: verify it's actually cgroup v2 by checking /proc/filesystems
	return isCgroupV2InFilesystems()
}

// isCgroupV2InFilesystems checks if cgroup2 filesystem is available in /proc/filesystems
func isCgroupV2InFilesystems() bool {
	data, err := os.ReadFile("/proc/filesystems")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "cgroup2")
}

// getCgroupV2Controllers reads available cgroup v2 controllers
func getCgroupV2Controllers() ([]string, error) {
	data, err := os.ReadFile(CgroupV2MountPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read cgroup v2 controllers: %w", err)
	}

	controllers := strings.Fields(strings.TrimSpace(string(data)))
	return controllers, nil
}

// GetSystemInfo returns detailed system information for debugging purposes
func GetSystemInfo(logger *zap.Logger) map[string]interface{} {
	info := make(map[string]interface{})

	// Kernel information
	if kernelVersion, err := kernel.GetKernelVersion(); err == nil {
		info["kernel_version"] = kernelVersion.String()
		info["kernel_compatible"] = kernel.CheckKernelVersion(MinKernelMajor, MinKernelMinor, MinKernelPatch)
	} else {
		info["kernel_version"] = "unknown"
		info["kernel_compatible"] = false
		logger.Warn("Could not retrieve kernel version for system info", zap.Error(err))
	}

	// Cgroup information
	info["cgroup_v2_available"] = isCgroupV2Available()
	if controllers, err := getCgroupV2Controllers(); err == nil {
		info["cgroup_v2_controllers"] = controllers
	}

	// OS information
	if hostname, err := os.Hostname(); err == nil {
		info["hostname"] = hostname
	}

	// Architecture information
	info["arch"] = getArchitecture()

	return info
}

// getArchitecture returns the system architecture
func getArchitecture() string {
	if data, err := os.ReadFile("/proc/version"); err == nil {
		version := string(data)
		if strings.Contains(version, "x86_64") {
			return "x86_64"
		} else if strings.Contains(version, "aarch64") || strings.Contains(version, "arm64") {
			return "arm64"
		} else if strings.Contains(version, "armv7") {
			return "armv7"
		}
	}
	return "unknown"
}

// ValidateEnvironment performs a comprehensive environment validation
func ValidateEnvironment(logger *zap.Logger) error {
	logger.Info("Starting Keploy environment validation")

	// Perform compatibility checks
	if err := isCompatible(logger); err != nil {
		// Log system info for debugging
		systemInfo := GetSystemInfo(logger)
		logger.Error("Environment validation failed", 
			zap.Any("system_info", systemInfo),
			zap.Error(err))
		return err
	}

	logger.Info("Environment validation completed successfully")
	return nil
}
