package oss

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"sealos-complik-admin/internal/infra/config"
)

type Uploader interface {
	Upload(ctx context.Context, objectKey string, reader io.Reader, contentType string) (string, error)
	DownloadByURL(ctx context.Context, fileURL string) (io.ReadCloser, string, error)
}

type Client struct {
	client        *minio.Client
	secure        bool
	endpoint      string
	bucketName    string
	publicBaseURL string
}

func NewClient(cfg config.OSSConfig) (*Client, error) {
	endpoint, secure, err := normalizeEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("oss endpoint is invalid: %w", err)
	}
	if strings.TrimSpace(cfg.Bucket) == "" {
		return nil, fmt.Errorf("oss bucket is required")
	}
	if strings.TrimSpace(cfg.AccessKeyID) == "" || strings.TrimSpace(cfg.AccessKeySecret) == "" {
		return nil, fmt.Errorf("oss access key is required")
	}

	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKeyID, cfg.AccessKeySecret, ""),
		Secure: secure,
	})
	if err != nil {
		return nil, fmt.Errorf("init oss client: %w", err)
	}

	return &Client{
		client:        client,
		secure:        secure,
		endpoint:      endpoint,
		bucketName:    cfg.Bucket,
		publicBaseURL: strings.TrimSpace(cfg.PublicBaseURL),
	}, nil
}

func (c *Client) Upload(ctx context.Context, objectKey string, reader io.Reader, contentType string) (string, error) {
	normalizedKey := strings.TrimLeft(strings.TrimSpace(objectKey), "/")
	if normalizedKey == "" {
		return "", fmt.Errorf("oss object key is required")
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("read upload body: %w", err)
	}

	options := minio.PutObjectOptions{}
	if strings.TrimSpace(contentType) != "" {
		options.ContentType = contentType
	}

	if _, err := c.client.PutObject(ctx, c.bucketName, normalizedKey, bytes.NewReader(body), int64(len(body)), options); err != nil {
		return "", fmt.Errorf("upload object to oss: %w", err)
	}

	return c.objectURL(normalizedKey), nil
}

func (c *Client) Download(ctx context.Context, objectKey string) (io.ReadCloser, string, error) {
	normalizedKey := strings.TrimLeft(strings.TrimSpace(objectKey), "/")
	if normalizedKey == "" {
		return nil, "", fmt.Errorf("oss object key is required")
	}

	object, err := c.client.GetObject(ctx, c.bucketName, normalizedKey, minio.GetObjectOptions{})
	if err != nil {
		return nil, "", fmt.Errorf("download object from oss: %w", err)
	}

	stat, err := object.Stat()
	if err != nil {
		_ = object.Close()
		return nil, "", fmt.Errorf("stat object from oss: %w", err)
	}

	contentType := strings.TrimSpace(stat.ContentType)
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	return object, contentType, nil
}

func (c *Client) DownloadByURL(ctx context.Context, fileURL string) (io.ReadCloser, string, error) {
	objectKey, err := c.objectKeyFromURL(fileURL)
	if err != nil {
		return nil, "", err
	}

	return c.Download(ctx, objectKey)
}

func (c *Client) objectURL(objectKey string) string {
	if c.publicBaseURL != "" {
		return strings.TrimRight(c.publicBaseURL, "/") + "/" + objectKey
	}

	scheme := "https"
	if !c.secure {
		scheme = "http"
	}

	return fmt.Sprintf("%s://%s/%s/%s", scheme, c.endpoint, c.bucketName, objectKey)
}

func (c *Client) objectKeyFromURL(fileURL string) (string, error) {
	trimmedURL := strings.TrimSpace(fileURL)
	if trimmedURL == "" {
		return "", fmt.Errorf("file url is required")
	}

	base := strings.TrimRight(c.objectURL(""), "/")
	if strings.HasPrefix(trimmedURL, base+"/") {
		return strings.TrimPrefix(trimmedURL, base+"/"), nil
	}

	parsed, err := url.Parse(trimmedURL)
	if err != nil {
		return "", fmt.Errorf("parse file url: %w", err)
	}
	normalizedPath := strings.Trim(parsed.Path, "/")
	bucketPrefix := strings.Trim(c.bucketName, "/") + "/"
	if strings.HasPrefix(normalizedPath, bucketPrefix) {
		return strings.TrimPrefix(normalizedPath, bucketPrefix), nil
	}

	return "", fmt.Errorf("invalid file url")
}

func normalizeEndpoint(raw string) (string, bool, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", false, fmt.Errorf("empty endpoint")
	}

	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		parsed, err := url.Parse(trimmed)
		if err != nil {
			return "", false, err
		}
		if parsed.Host == "" {
			return "", false, fmt.Errorf("invalid endpoint host")
		}
		if parsed.Path != "" && parsed.Path != "/" {
			return "", false, fmt.Errorf("endpoint must not contain path")
		}
		return parsed.Host, parsed.Scheme == "https", nil
	}

	if strings.Contains(trimmed, "/") {
		return "", false, fmt.Errorf("endpoint must be host[:port] or URL without path")
	}

	return trimmed, true, nil
}
