package ban

import (
	"context"
	"io"
)

type fileUploader interface {
	Upload(ctx context.Context, objectKey string, reader io.Reader, contentType string) (string, error)
	DownloadByURL(ctx context.Context, fileURL string) (io.ReadCloser, string, error)
}
