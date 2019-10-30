package github_test

import (
	"context"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/google/go-github/v28/github"
	"github.com/stretchr/testify/mock"
	"k8s.io/utils/clock"
	ct "k8s.io/utils/clock/testing"

	gh "github.com/aquasecurity/trivy-db/pkg/github"
)

type MockRepository struct {
	mock.Mock
}

func (_m *MockRepository) ListReleases(ctx context.Context, opt *github.ListOptions) (
	[]*github.RepositoryRelease, *github.Response, error) {
	ret := _m.Called(ctx, opt)
	ret0 := ret.Get(0)
	if ret0 == nil {
		return nil, nil, ret.Error(2)
	}
	releases, ok := ret0.([]*github.RepositoryRelease)
	if !ok {
		return nil, nil, ret.Error(2)
	}
	return releases, nil, ret.Error(2)
}

func (_m *MockRepository) GetReleaseByTag(ctx context.Context, tag string) (
	*github.RepositoryRelease, *github.Response, error) {
	ret := _m.Called(ctx, tag)
	ret0 := ret.Get(0)
	if ret0 == nil {
		return nil, nil, ret.Error(2)
	}
	release, ok := ret0.(*github.RepositoryRelease)
	if !ok {
		return nil, nil, ret.Error(2)
	}

	ret1 := ret.Get(1)
	if ret1 == nil {
		return nil, nil, ret.Error(2)
	}
	response, ok := ret1.(*github.Response)
	if !ok {
		return nil, nil, ret.Error(2)
	}

	return release, response, ret.Error(2)
}

func (_m *MockRepository) CreateRelease(ctx context.Context, release *github.RepositoryRelease) (
	*github.RepositoryRelease, *github.Response, error) {
	ret := _m.Called(ctx, release)
	ret0 := ret.Get(0)
	if ret0 == nil {
		return nil, nil, ret.Error(2)
	}
	release, ok := ret0.(*github.RepositoryRelease)
	if !ok {
		return nil, nil, ret.Error(2)
	}
	return release, nil, ret.Error(2)
}

func (_m *MockRepository) UploadReleaseAsset(ctx context.Context, id int64, opt *github.UploadOptions, file *os.File) (
	*github.ReleaseAsset, *github.Response, error) {
	ret := _m.Called(ctx, id, opt, file)
	ret0 := ret.Get(0)
	if ret0 == nil {
		return nil, nil, ret.Error(2)
	}
	asset, ok := ret0.(*github.ReleaseAsset)
	if !ok {
		return nil, nil, ret.Error(2)
	}
	return asset, nil, ret.Error(2)
}

func (_m *MockRepository) DeleteRelease(ctx context.Context, id int64) (*github.Response, error) {
	ret := _m.Called(ctx, id)
	ret0 := ret.Get(0)
	if ret0 == nil {
		return nil, ret.Error(1)
	}
	response, ok := ret0.(*github.Response)
	if !ok {
		return nil, ret.Error(1)
	}
	return response, ret.Error(1)
}

func (_m *MockRepository) DeleteRef(ctx context.Context, ref string) (*github.Response, error) {
	ret := _m.Called(ctx, ref)
	ret0 := ret.Get(0)
	if ret0 == nil {
		return nil, ret.Error(1)
	}
	response, ok := ret0.(*github.Response)
	if !ok {
		return nil, ret.Error(1)
	}
	return response, ret.Error(1)
}

func TestClient_UploadReleaseAsset(t *testing.T) {
	type listReleasesOutput struct {
		releases []*github.RepositoryRelease
		response *github.Response
		err      error
	}
	type listReleases struct {
		input  string
		output listReleasesOutput
	}

	type getReleaseByTagOutput struct {
		release  *github.RepositoryRelease
		response *github.Response
		err      error
	}
	type getReleaseByTag struct {
		input  string
		output getReleaseByTagOutput
	}

	type createReleaseOutput struct {
		release  *github.RepositoryRelease
		response *github.Response
		err      error
	}
	type createRelease struct {
		input  *github.RepositoryRelease
		output createReleaseOutput
	}

	type uploadReleaseAssetOutput struct {
		release  *github.ReleaseAsset
		response *github.Response
		err      error
	}
	type uploadReleaseAsset struct {
		input  int64
		output uploadReleaseAssetOutput
	}

	type deleteReleaseOutput struct {
		response *github.Response
		err      error
	}
	type deleteRelease struct {
		input  int64
		output deleteReleaseOutput
	}

	type deleteRefOutput struct {
		response *github.Response
		err      error
	}
	type deleteRef struct {
		input  string
		output deleteRefOutput
	}

	testCases := []struct {
		name               string
		clock              clock.Clock
		files              map[string][]byte
		filePaths          []string
		listReleases       []listReleases
		getReleaseByTag    []getReleaseByTag
		createRelease      []createRelease
		uploadReleaseAsset []uploadReleaseAsset
		deleteRelease      []deleteRelease
		deleteRef          []deleteRef
		expectedError      error
	}{
		{
			name:  "happy path with existed release",
			clock: ct.NewFakeClock(time.Date(2020, 12, 31, 23, 59, 59, 0, time.UTC)),
			files: map[string][]byte{
				"trivy.db.gz":       []byte("full"),
				"trivy-light.db.gz": []byte("light"),
			},
			filePaths: []string{
				"trivy.db.gz",
				"trivy-light.db.gz",
			},
			listReleases: []listReleases{
				{
					input: mock.Anything,
					output: listReleasesOutput{
						releases: []*github.RepositoryRelease{
							{
								ID:      github.Int64(1),
								Name:    github.String("v1-2020123000"),
								TagName: github.String("v1-2020123000"),
								PublishedAt: &github.Timestamp{
									Time: time.Date(2020, 12, 31, 23, 59, 59, 0, time.UTC),
								},
							},
						},
					},
				},
			},
			getReleaseByTag: []getReleaseByTag{
				{
					input: "v1-2020123123",
					output: getReleaseByTagOutput{
						release: &github.RepositoryRelease{
							ID:      github.Int64(1),
							TagName: github.String("v1-2020123123"),
						},
						response: &github.Response{
							Response: &http.Response{
								StatusCode: 200,
							},
						},
						err: nil,
					},
				},
			},
			uploadReleaseAsset: []uploadReleaseAsset{
				{
					input:  1,
					output: uploadReleaseAssetOutput{},
				},
			},
		},
		{
			name:  "happy path with non-existed release",
			clock: ct.NewFakeClock(time.Date(2020, 12, 31, 23, 59, 59, 0, time.UTC)),
			files: map[string][]byte{
				"trivy.db.gz":       []byte("full"),
				"trivy-light.db.gz": []byte("light"),
			},
			filePaths: []string{
				"trivy.db.gz",
				"trivy-light.db.gz",
			},
			listReleases: []listReleases{
				{
					input: mock.Anything,
					output: listReleasesOutput{
						releases: []*github.RepositoryRelease{
							{
								ID:      github.Int64(100),
								Name:    github.String("v1-2020123000"),
								TagName: github.String("v1-2020123000"),
								PublishedAt: &github.Timestamp{
									Time: time.Date(2020, 12, 31, 23, 59, 59, 0, time.UTC),
								},
							},
						},
					},
				},
			},
			getReleaseByTag: []getReleaseByTag{
				{
					input: "v1-2020123123",
					output: getReleaseByTagOutput{
						release: &github.RepositoryRelease{
							ID:      github.Int64(1),
							TagName: github.String("v1-2020123123"),
						},
						response: &github.Response{
							Response: &http.Response{
								StatusCode: 404,
							},
						},
						err: nil,
					},
				},
			},
			createRelease: []createRelease{
				{
					input: &github.RepositoryRelease{
						TagName:    github.String("v1-2020123123"),
						Name:       github.String("v1-2020123123"),
						Draft:      github.Bool(false),
						Prerelease: github.Bool(false),
					},
					output: createReleaseOutput{
						release: &github.RepositoryRelease{
							ID:      github.Int64(1),
							TagName: github.String("v1-2020123123"),
						},
					},
				},
			},
			uploadReleaseAsset: []uploadReleaseAsset{
				{
					input:  1,
					output: uploadReleaseAssetOutput{},
				},
			},
		},
		{
			name:  "happy path with old releases",
			clock: ct.NewFakeClock(time.Date(2019, 1, 30, 11, 59, 59, 0, time.UTC)),
			files: map[string][]byte{
				"trivy.db.gz":       []byte("full"),
				"trivy-light.db.gz": []byte("light"),
				"trivy-dummy":       []byte("dummy"),
			},
			filePaths: []string{
				"trivy.db.gz",
				"trivy-light.db.gz",
			},
			listReleases: []listReleases{
				{
					input: mock.Anything,
					output: listReleasesOutput{
						releases: []*github.RepositoryRelease{
							{
								ID:      github.Int64(111),
								Name:    github.String("v1-2019012023"),
								TagName: github.String("v1-2019012023"),
								PublishedAt: &github.Timestamp{
									Time: time.Date(2019, 1, 20, 23, 59, 59, 0, time.UTC),
								},
							},
							{
								ID:      github.Int64(222),
								Name:    github.String("v1-2019012509"),
								TagName: github.String("v1-2019012509"),
								PublishedAt: &github.Timestamp{
									Time: time.Date(2019, 1, 25, 9, 0, 59, 0, time.UTC),
								},
							},
						},
					},
				},
			},
			getReleaseByTag: []getReleaseByTag{
				{
					input: "v1-2019013011",
					output: getReleaseByTagOutput{
						release: &github.RepositoryRelease{
							ID:      github.Int64(2),
							TagName: github.String("v1-2019013011"),
						},
						response: &github.Response{
							Response: &http.Response{
								StatusCode: 200,
							},
						},
						err: nil,
					},
				},
			},
			uploadReleaseAsset: []uploadReleaseAsset{
				{
					input:  2,
					output: uploadReleaseAssetOutput{},
				},
			},
			deleteRelease: []deleteRelease{
				{
					input:  111,
					output: deleteReleaseOutput{},
				},
				{
					input:  222,
					output: deleteReleaseOutput{},
				},
			},
			deleteRef: []deleteRef{
				{
					input:  "tags/v1-2019012023",
					output: deleteRefOutput{},
				},
				{
					input:  "tags/v1-2019012509",
					output: deleteRefOutput{},
				},
			},
		},
		{
			name:  "sad path: updateReleaseAsset failed",
			clock: ct.NewFakeClock(time.Date(2020, 12, 31, 23, 59, 59, 0, time.UTC)),
			getReleaseByTag: []getReleaseByTag{
				{
					input: "v1-2020123123",
					output: getReleaseByTagOutput{
						err: errors.New("GetReleaseByTag failed"),
					},
				},
			},
			expectedError: errors.New("failed to update release asset: GetReleaseByTag failed"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockRepo := new(MockRepository)
			for _, lr := range tc.listReleases {
				mockRepo.On("ListReleases", mock.Anything, lr.input).Return(
					lr.output.releases, lr.output.response, lr.output.err,
				)
			}
			for _, gr := range tc.getReleaseByTag {
				mockRepo.On("GetReleaseByTag", mock.Anything, gr.input).Return(
					gr.output.release, gr.output.response, gr.output.err,
				)
			}

			for _, cr := range tc.createRelease {
				mockRepo.On("CreateRelease", mock.Anything, cr.input).Return(
					cr.output.release, cr.output.response, cr.output.err,
				)
			}

			for _, ura := range tc.uploadReleaseAsset {
				mockRepo.On("UploadReleaseAsset", mock.Anything, ura.input, mock.Anything, mock.Anything).Return(
					ura.output.release, ura.output.response, ura.output.err,
				)
			}

			for _, dr := range tc.deleteRelease {
				mockRepo.On("DeleteRelease", mock.Anything, dr.input).Return(
					dr.output.response, dr.output.err,
				)
			}

			for _, dr := range tc.deleteRef {
				mockRepo.On("DeleteRef", mock.Anything, dr.input).Return(
					dr.output.response, dr.output.err,
				)
			}

			dir, err := ioutil.TempDir("", "trivy-db")
			assert.NoError(t, err, tc.name)
			defer os.RemoveAll(dir)

			for name, data := range tc.files {
				path := filepath.Join(dir, name)
				err = ioutil.WriteFile(path, data, 0644)
				assert.NoError(t, err, tc.name)
			}

			var filePaths []string
			for _, path := range tc.filePaths {
				filePaths = append(filePaths, filepath.Join(dir, path))
			}

			client := gh.Client{
				Repository: mockRepo,
				Clock:      tc.clock,
			}

			ctx := context.Background()
			err = client.UploadReleaseAsset(ctx, filePaths)

			switch {
			case tc.expectedError != nil:
				assert.EqualError(t, err, tc.expectedError.Error(), tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}
