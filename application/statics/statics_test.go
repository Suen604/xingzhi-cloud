package statics

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/cloudreve/Cloudreve/v4/application/constants"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/pkg/util"
)

type versionCheckLogger struct {
	logging.Logger
	errors []string
}

func (l *versionCheckLogger) Error(format string, args ...any) {
	l.errors = append(l.errors, fmt.Sprintf(format, args...))
}

func TestStaticResourceEditionCompatibility(t *testing.T) {
	t.Chdir(t.TempDir())
	previous := util.UseWorkingDir
	util.UseWorkingDir = true
	t.Cleanup(func() { util.UseWorkingDir = previous })

	for _, external := range []bool{false, true} {
		for _, pro := range []bool{false, true} {
			for _, tc := range []struct {
				name    string
				version string
				invalid bool
			}{
				{"cloudreve-frontend", constants.BackendVersion, false},
				{"cloudreve-frontend-pro", constants.BackendVersion, false},
				{"unrelated-frontend", constants.BackendVersion, true},
				{"cloudreve-frontend", "0.0.0", true},
			} {
				t.Run(fmt.Sprintf("external=%t/pro=%t/%s/%s", external, pro, tc.name, tc.version), func(t *testing.T) {
					data := []byte(fmt.Sprintf(`{"name":%q,"version":%q}`, tc.name, tc.version))
					resources := fstest.MapFS{
						"assets/build/version.json": &fstest.MapFile{Data: data},
					}
					if external {
						dir := util.DataPath(StaticFolder)
						if err := os.MkdirAll(dir, 0700); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(filepath.Join(dir, "version.json"), data, 0600); err != nil {
							t.Fatal(err)
						}
					}
					logger := &versionCheckLogger{Logger: logging.NewConsoleLogger(logging.LevelError)}
					fs, err := NewServerStaticFS(logger, resources, pro)
					if err != nil || fs == nil {
						t.Fatalf("failed to initialize static resources: %v", err)
					}
					if (len(logger.errors) > 0) != tc.invalid {
						t.Fatalf("unexpected resource version errors: %v", logger.errors)
					}
				})
			}
		}
	}
}
