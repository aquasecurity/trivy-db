package github

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/google/go-github/v28/github"
	"golang.org/x/oauth2"
	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	"github.com/aquasecurity/trivy-db/pkg/db"
)

const (
	owner      = "aquasecurity"
	repo       = "trivy-db"
	expiration = 3 * time.Hour
)

type RepositoryInterface interface {
	ListReleases(ctx context.Context, opt *github.ListOptions) ([]*github.RepositoryRelease, *github.Response, error)
	GetReleaseByTag(ctx context.Context, tag string) (*github.RepositoryRelease, *github.Response, error)
	CreateRelease(ctx context.Context, release *github.RepositoryRelease) (*github.RepositoryRelease, *github.Response, error)
	UploadReleaseAsset(ctx context.Context, id int64, opt *github.UploadOptions, file *os.File) (*github.ReleaseAsset, *github.Response, error)
	DeleteRelease(ctx context.Context, id int64) (*github.Response, error)
	DeleteRef(ctx context.Context, ref string) (*github.Response, error)
}

type Repository struct {
	repository *github.RepositoriesService
	git        *github.GitService
	owner      string
	repoName   string
}

func (r Repository) ListReleases(ctx context.Context, opt *github.ListOptions) ([]*github.RepositoryRelease, *github.Response, error) {
	return r.repository.ListReleases(ctx, r.owner, r.repoName, opt)
}

func (r Repository) GetReleaseByTag(ctx context.Context, tag string) (*github.RepositoryRelease, *github.Response, error) {
	return r.repository.GetReleaseByTag(ctx, r.owner, r.repoName, tag)
}

func (r Repository) CreateRelease(ctx context.Context, release *github.RepositoryRelease) (*github.RepositoryRelease, *github.Response, error) {
	return r.repository.CreateRelease(ctx, r.owner, r.repoName, release)
}

func (r Repository) UploadReleaseAsset(ctx context.Context, id int64, opt *github.UploadOptions, file *os.File) (*github.ReleaseAsset, *github.Response, error) {
	return r.repository.UploadReleaseAsset(ctx, r.owner, r.repoName, id, opt, file)
}

func (r Repository) DeleteRelease(ctx context.Context, id int64) (*github.Response, error) {
	return r.repository.DeleteRelease(ctx, r.owner, r.repoName, id)
}

func (r Repository) DeleteRef(ctx context.Context, ref string) (*github.Response, error) {
	return r.git.DeleteRef(ctx, r.owner, r.repoName, ref)
}

type Client struct {
	Clock      clock.Clock
	Repository RepositoryInterface
}

func NewClient(ctx context.Context) Client {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
	)
	tc := oauth2.NewClient(ctx, ts)
	gc := github.NewClient(tc)

	repo := Repository{
		repository: gc.Repositories,
		git:        gc.Git,
		owner:      owner,
		repoName:   repo,
	}

	return Client{
		Clock:      clock.RealClock{},
		Repository: repo,
	}
}

func (c Client) UploadReleaseAsset(ctx context.Context, filePaths []string) error {
	now := c.Clock.Now().UTC()
	date := now.Format("2006010215")

	tag := fmt.Sprintf("v%d-%s", db.SchemaVersion, date)
	if err := c.updateReleaseAsset(ctx, tag, filePaths); err != nil {
		return xerrors.Errorf("failed to update release asset: %w", err)
	}

	if err := c.deleteOldReleases(ctx, now); err != nil {
		return xerrors.Errorf("failed to delete old releases: %w", err)
	}

	return nil
}

func (c Client) updateReleaseAsset(ctx context.Context, tag string, filePaths []string) error {
	log.Printf("Update release assets, release: %s\n", tag)
	release, res, err := c.Repository.GetReleaseByTag(ctx, tag)
	if err != nil {
		return err
	}

	if res.StatusCode == http.StatusNotFound {
		release = &github.RepositoryRelease{
			TagName:    github.String(tag),
			Name:       github.String(tag),
			Draft:      github.Bool(false),
			Prerelease: github.Bool(false),
		}
		release, _, err = c.Repository.CreateRelease(ctx, release)
		if err != nil {
			return err
		}
	}

	for _, filePath := range filePaths {
		log.Printf("Update release assets, file: %s\n", filePath)
		name := filepath.Base(filePath)
		uploadOptions := github.UploadOptions{
			Name:      name,
			MediaType: "application/gzip",
		}
		f, err := os.Open(filePath)
		if err != nil {
			return err
		}

		_, _, err = c.Repository.UploadReleaseAsset(ctx, *release.ID, &uploadOptions, f)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c Client) deleteOldReleases(ctx context.Context, now time.Time) error {
	options := github.ListOptions{}
	releases, _, err := c.Repository.ListReleases(ctx, &options)
	if err != nil {
		return xerrors.Errorf("failed to list releases: %w", err)
	}
	for _, release := range releases {
		if now.Sub(release.PublishedAt.Time) > expiration {
			log.Printf("Delete the old release, name: %s, published_at: %s",
				release.GetName(), release.GetPublishedAt())
			_, err = c.Repository.DeleteRelease(ctx, *release.ID)
			if err != nil {
				return xerrors.Errorf("failed to delete a release: %w", err)
			}
			log.Printf("Delete the tag: %s", release.GetTagName())
			_, err = c.Repository.DeleteRef(ctx, fmt.Sprintf("tags/%s", release.GetTagName()))
			if err != nil {
				return xerrors.Errorf("failed to delete a tag: %w", err)
			}
		}
	}
	return nil
}
