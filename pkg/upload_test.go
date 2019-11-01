package pkg

import (
	"context"
	"errors"
	"io/ioutil"
	"os"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc"

	"github.com/stretchr/testify/assert"
)

type mockVCSClient struct {
	uploadReleaseAsset func(ctx context.Context, filePaths []string) error
}

func (mc mockVCSClient) UploadReleaseAsset(ctx context.Context, filePaths []string) error {
	if mc.uploadReleaseAsset != nil {
		return mc.uploadReleaseAsset(ctx, filePaths)
	}
	return nil
}

func TestAppConfig_Upload(t *testing.T) {
	testCases := []struct {
		name                    string
		uploadReleaseAssertFunc func(ctx context.Context, filePaths []string) error
		expectedError           error
		inputDir                string
	}{
		{
			name:          "happy path",
			expectedError: nil,
		},
		{
			name:          "sad path: bad input dir",
			expectedError: errors.New("open /path/to/nowhere: no such file or directory"),
			inputDir:      "/path/to/nowhere",
		},
		{
			name: "sad path: UploadReleaseAsset returns an error",
			uploadReleaseAssertFunc: func(ctx context.Context, filePaths []string) error {
				return errors.New("upload release assert failed")
			},
			expectedError: errors.New("upload release assert failed"),
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

		ac := AppConfig{Client: mockVCSClient{
			uploadReleaseAsset: tc.uploadReleaseAssertFunc,
		}}
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
