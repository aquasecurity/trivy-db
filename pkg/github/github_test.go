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

	"github.com/google/go-github/v38/github"
	"k8s.io/utils/clock"
	ct "k8s.io/utils/clock/testing"

	gh "github.com/aquasecurity/trivy-db/pkg/github"
)

func TestClient_UploadReleaseAssets(t *testing.T) {
	testCases := []struct {
		name               string
		clock              clock.Clock
		files              map[string][]byte
		filePaths          []string
		listReleases       []gh.ListReleasesExpectation
		getReleaseByTag    []gh.GetReleaseByTagExpectation
		createRelease      []gh.CreateReleaseExpectation
		uploadReleaseAsset []gh.UploadReleaseAssetExpectation
		deleteRelease      []gh.DeleteReleaseExpectation
		deleteRef          []gh.DeleteRefExpectation
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
			listReleases: []gh.ListReleasesExpectation{
				{
					Args: gh.ListReleasesArgs{
						CtxAnything: true,
						OptAnything: true,
					},
					Returns: gh.ListReleasesReturns{
						Releases: []*github.RepositoryRelease{
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
			getReleaseByTag: []gh.GetReleaseByTagExpectation{
				{
					Args: gh.GetReleaseByTagArgs{
						CtxAnything: true,
						Tag:         "v1-2020123123",
					},
					Returns: gh.GetReleaseByTagReturns{
						Release: &github.RepositoryRelease{
							ID:      github.Int64(1),
							TagName: github.String("v1-2020123123"),
						},
						Response: &github.Response{
							Response: &http.Response{
								StatusCode: 200,
							},
						},
						Err: nil,
					},
				},
			},
			uploadReleaseAsset: []gh.UploadReleaseAssetExpectation{
				{
					Args: gh.UploadReleaseAssetArgs{
						CtxAnything:  true,
						Id:           1,
						OptAnything:  true,
						FileAnything: true,
					},
					Returns: gh.UploadReleaseAssetReturns{},
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
			listReleases: []gh.ListReleasesExpectation{
				{
					Args: gh.ListReleasesArgs{
						CtxAnything: true,
						OptAnything: true,
					},
					Returns: gh.ListReleasesReturns{
						Releases: []*github.RepositoryRelease{
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
			getReleaseByTag: []gh.GetReleaseByTagExpectation{
				{
					Args: gh.GetReleaseByTagArgs{
						CtxAnything: true,
						Tag:         "v1-2020123123",
					},
					Returns: gh.GetReleaseByTagReturns{
						Release: &github.RepositoryRelease{
							ID:      github.Int64(1),
							TagName: github.String("v1-2020123123"),
						},
						Response: &github.Response{
							Response: &http.Response{
								StatusCode: http.StatusNotFound,
							},
						},
						Err: errors.New("not found"),
					},
				},
			},
			createRelease: []gh.CreateReleaseExpectation{
				{
					Args: gh.CreateReleaseArgs{
						CtxAnything: true,
						Release: &github.RepositoryRelease{
							TagName:    github.String("v1-2020123123"),
							Name:       github.String("v1-2020123123"),
							Draft:      github.Bool(false),
							Prerelease: github.Bool(false),
						},
					},
					Returns: gh.CreateReleaseReturns{
						Result: &github.RepositoryRelease{
							ID:      github.Int64(1),
							TagName: github.String("v1-2020123123"),
						},
					},
				},
			},
			uploadReleaseAsset: []gh.UploadReleaseAssetExpectation{
				{
					Args: gh.UploadReleaseAssetArgs{
						CtxAnything:  true,
						Id:           1,
						OptAnything:  true,
						FileAnything: true,
					},
					Returns: gh.UploadReleaseAssetReturns{},
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
			listReleases: []gh.ListReleasesExpectation{
				{
					Args: gh.ListReleasesArgs{
						CtxAnything: true,
						OptAnything: true,
					},
					Returns: gh.ListReleasesReturns{
						Releases: []*github.RepositoryRelease{
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
							{
								ID:      github.Int64(333),
								Name:    github.String("v1-2019013059"),
								TagName: github.String("v1-2019013059"),
								PublishedAt: &github.Timestamp{
									Time: time.Date(2019, 1, 30, 10, 59, 59, 0, time.UTC),
								},
							},
							{
								ID:      github.Int64(444),
								Name:    github.String("v1-2019013059"),
								TagName: github.String("v1-2019013059"),
								PublishedAt: &github.Timestamp{
									Time: time.Date(2019, 1, 30, 9, 59, 59, 0, time.UTC),
								},
							},
						},
					},
				},
			},
			getReleaseByTag: []gh.GetReleaseByTagExpectation{
				{
					Args: gh.GetReleaseByTagArgs{
						CtxAnything: true,
						Tag:         "v1-2019013011",
					},
					Returns: gh.GetReleaseByTagReturns{
						Release: &github.RepositoryRelease{
							ID:      github.Int64(2),
							TagName: github.String("v1-2019013011"),
						},
						Response: &github.Response{
							Response: &http.Response{
								StatusCode: 200,
							},
						},
						Err: nil,
					},
				},
			},
			uploadReleaseAsset: []gh.UploadReleaseAssetExpectation{
				{
					Args: gh.UploadReleaseAssetArgs{
						CtxAnything:  true,
						Id:           2,
						OptAnything:  true,
						FileAnything: true,
					},
					Returns: gh.UploadReleaseAssetReturns{},
				},
			},
			deleteRelease: []gh.DeleteReleaseExpectation{
				{
					Args: gh.DeleteReleaseArgs{
						CtxAnything: true,
						Id:          111,
					},
					Returns: gh.DeleteReleaseReturns{},
				},
			},
			deleteRef: []gh.DeleteRefExpectation{
				{
					Args: gh.DeleteRefArgs{
						CtxAnything: true,
						Ref:         "tags/v1-2019012023",
					},
					Returns: gh.DeleteRefReturns{},
				},
			},
		},
		{
			name:  "happy path with few old releases",
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
			listReleases: []gh.ListReleasesExpectation{
				{
					Args: gh.ListReleasesArgs{
						CtxAnything: true,
						OptAnything: true,
					},
					Returns: gh.ListReleasesReturns{
						Releases: []*github.RepositoryRelease{
							{
								ID:      github.Int64(111),
								Name:    github.String("v1-2019012023"),
								TagName: github.String("v1-2019012023"),
								PublishedAt: &github.Timestamp{
									Time: time.Date(2019, 1, 20, 23, 59, 59, 0, time.UTC),
								},
							},
						},
					},
				},
			},
			getReleaseByTag: []gh.GetReleaseByTagExpectation{
				{
					Args: gh.GetReleaseByTagArgs{
						CtxAnything: true,
						Tag:         "v1-2019013011",
					},
					Returns: gh.GetReleaseByTagReturns{
						Release: &github.RepositoryRelease{
							ID:      github.Int64(2),
							TagName: github.String("v1-2019013011"),
						},
						Response: &github.Response{
							Response: &http.Response{
								StatusCode: 200,
							},
						},
						Err: nil,
					},
				},
			},
			uploadReleaseAsset: []gh.UploadReleaseAssetExpectation{
				{
					Args: gh.UploadReleaseAssetArgs{
						CtxAnything:  true,
						Id:           2,
						OptAnything:  true,
						FileAnything: true,
					},
					Returns: gh.UploadReleaseAssetReturns{},
				},
			},
		},
		{
			name:  "sad path: updateReleaseAsset failed because GetReleaseByTag fails",
			clock: ct.NewFakeClock(time.Date(2020, 12, 31, 23, 59, 59, 0, time.UTC)),
			getReleaseByTag: []gh.GetReleaseByTagExpectation{
				{
					Args: gh.GetReleaseByTagArgs{
						CtxAnything: true,
						Tag:         "v1-2020123123",
					},
					Returns: gh.GetReleaseByTagReturns{
						Err: errors.New("GetReleaseByTag failed"),
					},
				},
			},
			expectedError: errors.New("failed to update release asset: unable to get a release by tag: GetReleaseByTag failed"),
		},
		{
			name:  "sad path: updateReleaseAsset failed because CreateRelease fails",
			clock: ct.NewFakeClock(time.Date(2020, 12, 31, 23, 59, 59, 0, time.UTC)),
			getReleaseByTag: []gh.GetReleaseByTagExpectation{
				{
					Args: gh.GetReleaseByTagArgs{
						CtxAnything: true,
						Tag:         "v1-2020123123",
					},
					Returns: gh.GetReleaseByTagReturns{
						Release: &github.RepositoryRelease{
							ID:      github.Int64(1),
							TagName: github.String("v1-2020123123"),
						},
						Response: &github.Response{
							Response: &http.Response{
								StatusCode: 404,
							},
						},
					},
				},
			},
			createRelease: []gh.CreateReleaseExpectation{
				{
					Args: gh.CreateReleaseArgs{
						CtxAnything: true,
						Release: &github.RepositoryRelease{
							TagName:    github.String("v1-2020123123"),
							Name:       github.String("v1-2020123123"),
							Draft:      github.Bool(false),
							Prerelease: github.Bool(false),
						},
					},
					Returns: gh.CreateReleaseReturns{
						Err: errors.New("CreateRelease failed"),
					},
				},
			},
			expectedError: errors.New("failed to update release asset: failed to create new release: CreateRelease failed"),
		},
		{
			name:  "sad path: updateReleaseAsset failed because UploadReleaseAsset fails",
			clock: ct.NewFakeClock(time.Date(2020, 12, 31, 23, 59, 59, 0, time.UTC)),
			files: map[string][]byte{
				"trivy.db.gz":       []byte("full"),
				"trivy-light.db.gz": []byte("light"),
			},
			filePaths: []string{
				"trivy.db.gz",
				"trivy-light.db.gz",
			},
			getReleaseByTag: []gh.GetReleaseByTagExpectation{
				{
					Args: gh.GetReleaseByTagArgs{
						Ctx: context.Background(),
						Tag: "v1-2020123123",
					},
					Returns: gh.GetReleaseByTagReturns{
						Release: &github.RepositoryRelease{
							ID:      github.Int64(1),
							TagName: github.String("v1-2020123123"),
						},
						Response: &github.Response{
							Response: &http.Response{
								StatusCode: 200,
							},
						},
						Err: nil,
					},
				},
			},
			uploadReleaseAsset: []gh.UploadReleaseAssetExpectation{
				{
					Args: gh.UploadReleaseAssetArgs{
						Ctx:          context.Background(),
						Id:           1,
						Opt:          &github.UploadOptions{Name: "trivy.db.gz", Label: "", MediaType: "application/gzip"},
						FileAnything: true,
					},
					Returns: gh.UploadReleaseAssetReturns{
						Err: errors.New("UploadReleaseAsset failed"),
					},
				},
			},
			expectedError: errors.New("failed to update release asset: unable to upload a release asset: UploadReleaseAsset failed"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockRepo := new(gh.MockRepositoryInterface)
			mockRepo.ApplyListReleasesExpectations(tc.listReleases)
			mockRepo.ApplyGetReleaseByTagExpectations(tc.getReleaseByTag)
			mockRepo.ApplyCreateReleaseExpectations(tc.createRelease)
			mockRepo.ApplyUploadReleaseAssetExpectations(tc.uploadReleaseAsset)
			mockRepo.ApplyDeleteReleaseExpectations(tc.deleteRelease)
			mockRepo.ApplyDeleteRefExpectations(tc.deleteRef)

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
			err = client.UploadReleaseAssets(ctx, filePaths)

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
