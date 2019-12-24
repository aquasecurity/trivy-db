package pkg

import (
	"errors"
	"io/ioutil"
	"os"
	"testing"

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
				Args:    github.UploadReleaseAssetsArgs{CtxAnything: true, FilePathsAnything: true},
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
		d, _ := ioutil.TempDir("", "TestAppConfig_Upload_*")
		defer func() {
			_ = os.RemoveAll(d)
		}()

		for i := 0; i < 5; i++ {
			f1, _ := ioutil.TempFile(d, "TestAppConfig_Upload_file-*.db.gz")
			f2, _ := ioutil.TempFile(d, "TestAppConfig_Upload_file-*.randomfile")
			_ = f1.Close()
			_ = f2.Close()
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
	}
}
