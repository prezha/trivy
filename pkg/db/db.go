package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/oci"
	"github.com/aquasecurity/trivy/pkg/version/doc"
)

const (
	SchemaVersion = db.SchemaVersion
	dbMediaType   = "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip"
)

var (
	DefaultRepository    = fmt.Sprintf("%s:%d", "ghcr.io/aquasecurity/trivy-db", db.SchemaVersion)
	defaultRepository, _ = name.NewTag(DefaultRepository)

	Init  = db.Init
	Close = db.Close
	Path  = db.Path
)

type options struct {
	artifact     *oci.Artifact
	dbRepository name.Reference
}

// Option is a functional option
type Option func(*options)

// WithOCIArtifact takes an OCI artifact
func WithOCIArtifact(art *oci.Artifact) Option {
	return func(opts *options) {
		opts.artifact = art
	}
}

// WithDBRepository takes a dbRepository
func WithDBRepository(dbRepository name.Reference) Option {
	return func(opts *options) {
		opts.dbRepository = dbRepository
	}
}

// Client implements DB operations
type Client struct {
	*options

	dbDir    string
	metadata metadata.Client
	quiet    bool
}

func Dir(cacheDir string) string {
	return filepath.Join(cacheDir, "db")
}

// NewClient is the factory method for DB client
func NewClient(dbDir string, quiet bool, opts ...Option) *Client {
	o := &options{
		dbRepository: defaultRepository,
	}

	for _, opt := range opts {
		opt(o)
	}

	return &Client{
		options:  o,
		dbDir:    dbDir,
		metadata: metadata.NewClient(dbDir),
		quiet:    quiet,
	}
}

// NeedsUpdate check is DB needs update
func (c *Client) NeedsUpdate(ctx context.Context, cliVersion string, skip bool) (bool, error) {
	meta, err := c.metadata.Get()
	if err != nil {
		log.Debug("There is no valid metadata file", log.Err(err))
		if skip {
			log.Error("The first run cannot skip downloading DB")
			return false, xerrors.New("--skip-update cannot be specified on the first run")
		}
		meta = metadata.Metadata{Version: db.SchemaVersion}
	}

	if db.SchemaVersion < meta.Version {
		log.Error("The Trivy version is old. Update to the latest version.", log.String("version", cliVersion))
		return false, xerrors.Errorf("the version of DB schema doesn't match. Local DB: %d, Expected: %d",
			meta.Version, db.SchemaVersion)
	}

	if skip {
		log.Debug("Skipping DB update...")
		if err = c.validate(meta); err != nil {
			return false, xerrors.Errorf("validate error: %w", err)
		}
		return false, nil
	}

	if db.SchemaVersion != meta.Version {
		log.Debug("The local DB schema version does not match with supported version schema.",
			log.Int("local_version", meta.Version), log.Int("supported_version", db.SchemaVersion))
		return true, nil
	}

	return !c.isNewDB(ctx, meta), nil
}

func (c *Client) validate(meta metadata.Metadata) error {
	if db.SchemaVersion != meta.Version {
		log.Error("The local DB has an old schema version which is not supported by the current version of Trivy CLI. DB needs to be updated.")
		return xerrors.Errorf("--skip-update cannot be specified with the old DB schema. Local DB: %d, Expected: %d",
			meta.Version, db.SchemaVersion)
	}
	return nil
}

func (c *Client) isNewDB(ctx context.Context, meta metadata.Metadata) bool {
	now := clock.Now(ctx)
	if now.Before(meta.NextUpdate) {
		log.Debug("DB update was skipped because the local DB is the latest")
		return true
	}

	if now.Before(meta.DownloadedAt.Add(time.Hour)) {
		log.Debug("DB update was skipped because the local DB was downloaded during the last hour")
		return true
	}
	return false
}

// Download downloads the DB file
func (c *Client) Download(ctx context.Context, dst string, opt types.RegistryOptions) error {
	// Remove the metadata file under the cache directory before downloading DB
	if err := c.metadata.Delete(); err != nil {
		log.Debug("No metadata file")
	}

	art := c.initOCIArtifact(opt)

	// retry on non-fatal errors
	download := func() error {
		if err := art.Download(ctx, dst, oci.DownloadOption{MediaType: dbMediaType}); err != nil {
			// handle transport errors
			var terr *transport.Error
			if errors.As(err, &terr) {
				// retry on TOOMANYREQUESTS non-fatal error, but only if there are no other errors
				if len(terr.Errors) == 1 && terr.Errors[0].Code == transport.TooManyRequestsErrorCode {
					log.Warnf("Non-fatal error, will retry: %v", err)
					return err
				}

				// handle fatal errors
				// collect transport error codes
				var codes []transport.ErrorCode
				for _, c := range terr.Errors {
					codes = append(codes, c.Code)
				}

				// if any of these specific errors codes are present, reference docs for better user experience
				if slices.Contains(codes, transport.DeniedErrorCode) || slices.Contains(codes, transport.UnauthorizedErrorCode) {
					// e.g. https://aquasecurity.github.io/trivy/latest/docs/references/troubleshooting/#db
					log.Warnf("See %s", doc.URL("/docs/references/troubleshooting/", "db"))
				}
			}
			// return permanent error to stop retrying
			return backoff.Permanent(err)
		}
		return nil
	}
	// retry with exponential backoff (up to DefaultMaxElapsedTime of 15 mins), taking context into account
	b := backoff.WithContext(backoff.NewExponentialBackOff(), ctx)
	if err := backoff.Retry(download, b); err != nil {
		return xerrors.Errorf("database download error: %w", err)
	}

	if err := c.updateDownloadedAt(ctx, dst); err != nil {
		return xerrors.Errorf("failed to update downloaded_at: %w", err)
	}
	return nil
}

func (c *Client) Clear(_ context.Context) error {
	if err := os.RemoveAll(c.dbDir); err != nil {
		return xerrors.Errorf("failed to remove vulnerability database: %w", err)
	}
	return nil
}

func (c *Client) updateDownloadedAt(ctx context.Context, dbDir string) error {
	log.Debug("Updating database metadata...")

	// We have to initialize a metadata client here
	// since the destination may be different from the cache directory.
	client := metadata.NewClient(dbDir)
	meta, err := client.Get()
	if err != nil {
		return xerrors.Errorf("unable to get metadata: %w", err)
	}

	meta.DownloadedAt = clock.Now(ctx).UTC()
	if err = client.Update(meta); err != nil {
		return xerrors.Errorf("failed to update metadata: %w", err)
	}

	return nil
}

func (c *Client) initOCIArtifact(opt types.RegistryOptions) *oci.Artifact {
	if c.artifact != nil {
		return c.artifact
	}
	return oci.NewArtifact(c.dbRepository.String(), c.quiet, opt)
}

func (c *Client) ShowInfo() error {
	meta, err := c.metadata.Get()
	if err != nil {
		return xerrors.Errorf("something wrong with DB: %w", err)
	}
	log.Debug("DB info", log.Int("schema", meta.Version), log.Time("updated_at", meta.UpdatedAt),
		log.Time("next_update", meta.NextUpdate), log.Time("downloaded_at", meta.DownloadedAt))
	return nil
}
