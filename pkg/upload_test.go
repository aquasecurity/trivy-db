package pkg

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-db/pkg/github"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc"
)

func TestAppConfig_Upload(t *testing.T) {
	testCases := []struct {
		name                string
		uploadReleaseAssert github.UploadReleaseAssetsExpectation
		expectedError       error
		inputDir            string
	}{
		{
			name: "happy path",
			uploadReleaseAssert: github.UploadReleaseAssetsExpectation{
				Args: github.UploadReleaseAssetsArgs{
					CtxAnything: true,
					FilePaths: []string{
						filepath.Join(os.TempDir(), "TestAppConfig_Upload_Dir", "TestAppConfig_Upload-0.db.gz"),
						filepath.Join(os.TempDir(), "TestAppConfig_Upload_Dir", "TestAppConfig_Upload-0.db.tgz"),
						filepath.Join(os.TempDir(), "TestAppConfig_Upload_Dir", "TestAppConfig_Upload-1.db.gz"),
						filepath.Join(os.TempDir(), "TestAppConfig_Upload_Dir", "TestAppConfig_Upload-1.db.tgz"),
						filepath.Join(os.TempDir(), "TestAppConfig_Upload_Dir", "TestAppConfig_Upload-2.db.gz"),
						filepath.Join(os.TempDir(), "TestAppConfig_Upload_Dir", "TestAppConfig_Upload-2.db.tgz"),
						filepath.Join(os.TempDir(), "TestAppConfig_Upload_Dir", "TestAppConfig_Upload-3.db.gz"),
						filepath.Join(os.TempDir(), "TestAppConfig_Upload_Dir", "TestAppConfig_Upload-3.db.tgz"),
						filepath.Join(os.TempDir(), "TestAppConfig_Upload_Dir", "TestAppConfig_Upload-4.db.gz"),
						filepath.Join(os.TempDir(), "TestAppConfig_Upload_Dir", "TestAppConfig_Upload-4.db.tgz"),
					},
				},
				Returns: github.UploadReleaseAssetsReturns{},
			},
			expectedError: nil,
		},
		{
			name:          "sad path: bad input dir",
			expectedError: errors.New("unable to list files: open /path/to/nowhere: no such file or directory"),
			uploadReleaseAssert: github.UploadReleaseAssetsExpectation{
				Args:    github.UploadReleaseAssetsArgs{CtxAnything: true, FilePathsAnything: true},
				Returns: github.UploadReleaseAssetsReturns{},
			},
			inputDir: "/path/to/nowhere",
		},
		{
			name: "sad path: UploadReleaseAsset returns an error",
			uploadReleaseAssert: github.UploadReleaseAssetsExpectation{
				Args: github.UploadReleaseAssetsArgs{CtxAnything: true, FilePathsAnything: true},
				Returns: github.UploadReleaseAssetsReturns{
					Err: errors.New("upload release assert failed"),
				},
			},
			expectedError: errors.New("failed to upload a release asset: upload release assert failed"),
		},
	}

	for _, tc := range testCases {
		t.Run("upload tests", func(t *testing.T) {
			d := filepath.Join(os.TempDir(), "TestAppConfig_Upload_Dir")
			require.NoError(t, os.Mkdir(d, 0700))
			defer func() {
				_ = os.RemoveAll(d)
			}()

			for i := 0; i < 5; i++ {
				f1, err := os.Create(filepath.Join(d, fmt.Sprintf("TestAppConfig_Upload-%d.db.gz", i)))
				require.NoError(t, err)
				f2, err := os.Create(filepath.Join(d, fmt.Sprintf("TestAppConfig_Upload-%d.randomfile", i)))
				require.NoError(t, err)
				f3, err := os.Create(filepath.Join(d, fmt.Sprintf("TestAppConfig_Upload-%d.db.tgz", i)))
				require.NoError(t, err)
				_ = f1.Close()
				_ = f2.Close()
				_ = f3.Close()
			}

			switch {
			case tc.inputDir != "":
				vulnsrc.UpdateList = []string{tc.inputDir}
			default:
				vulnsrc.UpdateList = []string{d}
			}

			mockVCSClient := new(github.MockVCSClientInterface)
			mockVCSClient.ApplyUploadReleaseAssetsExpectation(tc.uploadReleaseAssert)

			ac := AppConfig{Client: mockVCSClient}
			cliApp := ac.NewApp("1.2.3")

			err := cliApp.Run([]string{"trivy-db", "upload"})

			switch {
			case tc.expectedError != nil:
				assert.Equal(t, tc.expectedError.Error(), err.Error(), tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}
		})
	}
}
