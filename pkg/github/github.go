package github

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"

	"github.com/google/go-github/v28/github"
	"golang.org/x/oauth2"
)

const (
	owner      = "aquasecurity"
	repo       = "trivy-db"
	expiration = 1 * 24 * time.Hour
)

func UploadReleaseAsset(filePaths []string) error {
	ctx := context.Background()
	client := newClient(ctx)

	now := time.Now().UTC()
	date := now.Format("2006010215")

	tag := fmt.Sprintf("v%d-%s", db.SchemaVersion, date)
	if err := updateReleaseAsset(ctx, client, tag, filePaths); err != nil {
		return xerrors.Errorf("failed to update release asset: %w", err)
	}

	if err := deleteOldReleases(ctx, client, now); err != nil {
		return xerrors.Errorf("failed to delete old releases: %w", err)
	}

	return nil
}

func updateReleaseAsset(ctx context.Context, client *github.Client, tag string, filePaths []string) error {
	log.Printf("Update release assets, release: %s\n", tag)
	release, res, err := client.Repositories.GetReleaseByTag(ctx, owner, repo, tag)

	if res.StatusCode == 404 {
		release = &github.RepositoryRelease{
			TagName:    github.String(tag),
			Name:       github.String(tag),
			Draft:      github.Bool(false),
			Prerelease: github.Bool(false),
		}
		release, _, err = client.Repositories.CreateRelease(ctx, owner, repo, release)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
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

		_, _, err = client.Repositories.UploadReleaseAsset(ctx, owner, repo, *release.ID, &uploadOptions, f)
		if err != nil {
			return err
		}
	}
	return nil
}

func deleteOldReleases(ctx context.Context, client *github.Client, now time.Time) error {
	options := github.ListOptions{}
	releases, _, err := client.Repositories.ListReleases(ctx, owner, repo, &options)
	if err != nil {
		return xerrors.Errorf("failed to list releases: %w", err)
	}
	for _, release := range releases {
		if now.Sub(release.PublishedAt.Time) > expiration {
			log.Printf("Delete the old release, name: %s, published_at: %s",
				release.GetName(), release.GetPublishedAt())
			_, err = client.Repositories.DeleteRelease(ctx, owner, repo, *release.ID)
			if err != nil {
				return xerrors.Errorf("failed to delete a release: %w", err)
			}
			log.Printf("Delete the tag: %s", release.GetTagName())
			_, err = client.Git.DeleteRef(ctx, owner, repo, fmt.Sprintf("tags/%s", release.GetTagName()))
			if err != nil {
				return xerrors.Errorf("failed to delete a tag: %w", err)
			}
		}
	}
	return nil
}

func newClient(ctx context.Context) *github.Client {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
	)
	tc := oauth2.NewClient(ctx, ts)

	return github.NewClient(tc)
}
