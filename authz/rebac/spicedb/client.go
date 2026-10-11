package spicedb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"time"

	pb "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"github.com/authzed/spicedb/pkg/cmd/datastore"
	"github.com/authzed/spicedb/pkg/cmd/server"
	"github.com/authzed/spicedb/pkg/cmd/util"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client provides authorization operations backed by SpiceDB.
type Client struct {
	permClient   pb.PermissionsServiceClient
	schemaClient pb.SchemaServiceClient
	conn         *grpc.ClientConn
	embedded     bool
	logger       *slog.Logger
}

// Config holds SpiceDB client configuration.
type Config struct {
	// Mode: "embedded" or "remote"
	Mode string `json:"mode" yaml:"mode"`

	// Embedded mode settings
	// DatastoreEngine: "memory" or "postgres"
	DatastoreEngine string `json:"datastore_engine,omitempty" yaml:"datastore_engine,omitempty"`
	// DatastoreURI: connection string for postgres
	DatastoreURI string `json:"datastore_uri,omitempty" yaml:"datastore_uri,omitempty"`

	// Remote mode settings
	// Endpoint: SpiceDB gRPC endpoint (e.g., "localhost:50051")
	Endpoint string `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`
	// Token: preshared key for authentication
	Token string `json:"token,omitempty" yaml:"token,omitempty"`
	// Insecure: skip TLS verification
	Insecure bool `json:"insecure,omitempty" yaml:"insecure,omitempty"`
}

// DefaultConfig returns a default configuration for embedded mode.
func DefaultConfig() Config {
	return Config{
		Mode:            "embedded",
		DatastoreEngine: "memory",
	}
}

// NewClient creates a new SpiceDB client based on configuration.
func NewClient(ctx context.Context, cfg Config, logger *slog.Logger) (*Client, error) {
	if logger == nil {
		logger = slog.Default()
	}

	switch cfg.Mode {
	case "embedded", "":
		return newEmbeddedClient(ctx, cfg, logger)
	case "remote":
		return newRemoteClient(ctx, cfg, logger)
	default:
		return nil, fmt.Errorf("unknown authz mode: %s", cfg.Mode)
	}
}

// newEmbeddedClient creates an embedded SpiceDB instance.
func newEmbeddedClient(ctx context.Context, cfg Config, logger *slog.Logger) (*Client, error) {
	engine := cfg.DatastoreEngine
	if engine == "" {
		engine = "memory"
	}

	// Create datastore
	var dsOpts []datastore.ConfigOption
	dsOpts = append(dsOpts, datastore.WithEngine(engine))
	if cfg.DatastoreURI != "" {
		dsOpts = append(dsOpts, datastore.WithURI(cfg.DatastoreURI))
	}

	ds, err := datastore.NewDatastore(ctx, dsOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create datastore: %w", err)
	}

	// Use a random preshared key for embedded mode
	presharedKey := "embedded-dev-key-" + fmt.Sprintf("%d", time.Now().UnixNano())

	// Find an available port
	port, err := findAvailablePort()
	if err != nil {
		return nil, fmt.Errorf("failed to find available port: %w", err)
	}
	address := fmt.Sprintf("127.0.0.1:%d", port)

	// Create server configuration with TCP on the available port
	serverCfg := server.NewConfigWithOptionsAndDefaults(
		server.WithDatastore(ds),
		server.WithPresharedSecureKey(presharedKey),
		server.WithGRPCServer(util.GRPCServerConfig{
			Network: "tcp",
			Address: address,
			Enabled: true,
		}),
		server.WithDispatchServer(util.GRPCServerConfig{
			Enabled: false,
		}),
		server.WithHTTPGateway(util.HTTPServerConfig{
			HTTPEnabled: false,
		}),
	)

	// Complete and start the server
	runnableServer, err := serverCfg.Complete(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to complete server config: %w", err)
	}

	// Start server in background
	go func() {
		if err := runnableServer.Run(ctx); err != nil {
			logger.Error("SpiceDB server error", "error", err)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Connect to the running server via gRPC
	conn, err := grpc.NewClient(address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpcutil.WithInsecureBearerToken(presharedKey),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to dial embedded SpiceDB: %w", err)
	}

	// Suppress unused variable warning - server runs in background goroutine
	_ = runnableServer

	logger.Info("started embedded SpiceDB", "engine", engine)

	return &Client{
		permClient:   pb.NewPermissionsServiceClient(conn),
		schemaClient: pb.NewSchemaServiceClient(conn),
		conn:         conn,
		embedded:     true,
		logger:       logger,
	}, nil
}

// newRemoteClient creates a client connected to a remote SpiceDB instance.
func newRemoteClient(ctx context.Context, cfg Config, logger *slog.Logger) (*Client, error) {
	// Check for context cancellation before connecting
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("remote endpoint is required")
	}

	var opts []grpc.DialOption

	if cfg.Insecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		systemCerts, err := grpcutil.WithSystemCerts(grpcutil.VerifyCA)
		if err != nil {
			return nil, fmt.Errorf("failed to load system certs: %w", err)
		}
		opts = append(opts, systemCerts)
	}

	if cfg.Token != "" {
		opts = append(opts, grpcutil.WithBearerToken(cfg.Token))
	}

	client, err := authzed.NewClient(cfg.Endpoint, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SpiceDB: %w", err)
	}

	logger.Info("connected to remote SpiceDB", "endpoint", cfg.Endpoint)

	return &Client{
		permClient:   client.PermissionsServiceClient,
		schemaClient: client.SchemaServiceClient,
		embedded:     false,
		logger:       logger,
	}, nil
}

// Close closes the client connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// IsEmbedded returns true if this client is using an embedded SpiceDB instance.
func (c *Client) IsEmbedded() bool {
	return c.embedded
}

// WriteSchema writes the authorization schema.
func (c *Client) WriteSchema(ctx context.Context, schema string) error {
	_, err := c.schemaClient.WriteSchema(ctx, &pb.WriteSchemaRequest{
		Schema: schema,
	})
	if err != nil {
		return fmt.Errorf("failed to write schema: %w", err)
	}
	c.logger.Debug("wrote schema to SpiceDB")
	return nil
}

// ReadSchema reads the current authorization schema.
func (c *Client) ReadSchema(ctx context.Context) (string, error) {
	resp, err := c.schemaClient.ReadSchema(ctx, &pb.ReadSchemaRequest{})
	if err != nil {
		return "", fmt.Errorf("failed to read schema: %w", err)
	}
	return resp.SchemaText, nil
}

// Check checks if a subject has a permission on a resource.
func (c *Client) Check(ctx context.Context, req *CheckRequest) (bool, error) {
	resp, err := c.permClient.CheckPermission(ctx, &pb.CheckPermissionRequest{
		Consistency: &pb.Consistency{
			Requirement: &pb.Consistency_FullyConsistent{FullyConsistent: true},
		},
		Resource: &pb.ObjectReference{
			ObjectType: req.ResourceType,
			ObjectId:   req.ResourceID,
		},
		Permission: req.Permission,
		Subject: &pb.SubjectReference{
			Object: &pb.ObjectReference{
				ObjectType: req.SubjectType,
				ObjectId:   req.SubjectID,
			},
		},
	})
	if err != nil {
		return false, fmt.Errorf("permission check failed: %w", err)
	}

	return resp.Permissionship == pb.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION, nil
}

// WriteRelationship writes a relationship tuple.
func (c *Client) WriteRelationship(ctx context.Context, rel *Relationship) error {
	_, err := c.permClient.WriteRelationships(ctx, &pb.WriteRelationshipsRequest{
		Updates: []*pb.RelationshipUpdate{
			{
				Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: rel.ResourceType,
						ObjectId:   rel.ResourceID,
					},
					Relation: rel.Relation,
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: rel.SubjectType,
							ObjectId:   rel.SubjectID,
						},
					},
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to write relationship: %w", err)
	}
	return nil
}

// ReplaceRelationships deletes and then writes relationship tuples in one
// atomic request: a reader sees either the old set or the new one. Deleting
// a tuple that does not exist is not an error.
func (c *Client) ReplaceRelationships(ctx context.Context, deletes, writes []*Relationship) error {
	updates := make([]*pb.RelationshipUpdate, 0, len(deletes)+len(writes))
	add := func(op pb.RelationshipUpdate_Operation, rels []*Relationship) {
		for _, rel := range rels {
			updates = append(updates, &pb.RelationshipUpdate{
				Operation: op,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{ObjectType: rel.ResourceType, ObjectId: rel.ResourceID},
					Relation: rel.Relation,
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{ObjectType: rel.SubjectType, ObjectId: rel.SubjectID},
					},
				},
			})
		}
	}
	// SpiceDB rejects one request that names the same tuple twice, so a
	// tuple in both lists is written, not deleted.
	var keep []*Relationship
	for _, d := range deletes {
		if !slices.ContainsFunc(writes, func(w *Relationship) bool { return *w == *d }) {
			keep = append(keep, d)
		}
	}
	add(pb.RelationshipUpdate_OPERATION_DELETE, keep)
	add(pb.RelationshipUpdate_OPERATION_TOUCH, writes)
	if len(updates) == 0 {
		return nil
	}
	if _, err := c.permClient.WriteRelationships(ctx, &pb.WriteRelationshipsRequest{Updates: updates}); err != nil {
		return fmt.Errorf("failed to replace relationships: %w", err)
	}
	return nil
}

// WriteRelationships writes multiple relationship tuples atomically.
func (c *Client) WriteRelationships(ctx context.Context, rels []*Relationship) error {
	updates := make([]*pb.RelationshipUpdate, len(rels))
	for i, rel := range rels {
		updates[i] = &pb.RelationshipUpdate{
			Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &pb.Relationship{
				Resource: &pb.ObjectReference{
					ObjectType: rel.ResourceType,
					ObjectId:   rel.ResourceID,
				},
				Relation: rel.Relation,
				Subject: &pb.SubjectReference{
					Object: &pb.ObjectReference{
						ObjectType: rel.SubjectType,
						ObjectId:   rel.SubjectID,
					},
				},
			},
		}
	}

	_, err := c.permClient.WriteRelationships(ctx, &pb.WriteRelationshipsRequest{
		Updates: updates,
	})
	if err != nil {
		return fmt.Errorf("failed to write relationships: %w", err)
	}
	return nil
}

// DeleteRelationship deletes a relationship tuple.
func (c *Client) DeleteRelationship(ctx context.Context, rel *Relationship) error {
	_, err := c.permClient.WriteRelationships(ctx, &pb.WriteRelationshipsRequest{
		Updates: []*pb.RelationshipUpdate{
			{
				Operation: pb.RelationshipUpdate_OPERATION_DELETE,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: rel.ResourceType,
						ObjectId:   rel.ResourceID,
					},
					Relation: rel.Relation,
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: rel.SubjectType,
							ObjectId:   rel.SubjectID,
						},
					},
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to delete relationship: %w", err)
	}
	return nil
}

// RelationshipFilter selects stored relationships. ResourceType is
// required; empty fields match anything. SubjectID requires SubjectType.
type RelationshipFilter struct {
	ResourceType string
	ResourceID   string
	Relation     string
	SubjectType  string
	SubjectID    string
}

// DeleteRelationships deletes every stored relationship matching filter in
// one atomic request. Deleting nothing is not an error.
func (c *Client) DeleteRelationships(ctx context.Context, filter *RelationshipFilter) error {
	if filter.ResourceType == "" {
		return fmt.Errorf("delete relationships: filter requires a resource type")
	}
	if filter.SubjectID != "" && filter.SubjectType == "" {
		return fmt.Errorf("delete relationships: a subject ID requires a subject type")
	}
	f := &pb.RelationshipFilter{
		ResourceType:       filter.ResourceType,
		OptionalResourceId: filter.ResourceID,
		OptionalRelation:   filter.Relation,
	}
	if filter.SubjectType != "" {
		f.OptionalSubjectFilter = &pb.SubjectFilter{
			SubjectType:       filter.SubjectType,
			OptionalSubjectId: filter.SubjectID,
		}
	}
	if _, err := c.permClient.DeleteRelationships(ctx, &pb.DeleteRelationshipsRequest{RelationshipFilter: f}); err != nil {
		return fmt.Errorf("failed to delete relationships: %w", err)
	}
	return nil
}

// LookupSubjects finds all subjects with a given permission on a resource.
func (c *Client) LookupSubjects(ctx context.Context, req *LookupSubjectsRequest) ([]string, error) {
	stream, err := c.permClient.LookupSubjects(ctx, &pb.LookupSubjectsRequest{
		Consistency: &pb.Consistency{
			Requirement: &pb.Consistency_FullyConsistent{FullyConsistent: true},
		},
		Resource: &pb.ObjectReference{
			ObjectType: req.ResourceType,
			ObjectId:   req.ResourceID,
		},
		Permission:        req.Permission,
		SubjectObjectType: req.SubjectType,
	})
	if err != nil {
		return nil, fmt.Errorf("lookup subjects failed: %w", err)
	}

	var subjects []string
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("lookup subjects failed: %w", err)
		}
		subjects = append(subjects, resp.Subject.SubjectObjectId)
	}
	return subjects, nil
}

// LookupResources finds all resources a subject has permission on.
func (c *Client) LookupResources(ctx context.Context, req *LookupResourcesRequest) ([]string, error) {
	stream, err := c.permClient.LookupResources(ctx, &pb.LookupResourcesRequest{
		Consistency: &pb.Consistency{
			Requirement: &pb.Consistency_FullyConsistent{FullyConsistent: true},
		},
		ResourceObjectType: req.ResourceType,
		Permission:         req.Permission,
		Subject: &pb.SubjectReference{
			Object: &pb.ObjectReference{
				ObjectType: req.SubjectType,
				ObjectId:   req.SubjectID,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("lookup resources failed: %w", err)
	}

	var resources []string
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("lookup resources failed: %w", err)
		}
		resources = append(resources, resp.ResourceObjectId)
	}
	return resources, nil
}

// findAvailablePort finds an available TCP port by listening on :0 and then closing.
func findAvailablePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		return 0, fmt.Errorf("releasing port %d: %w", port, err)
	}
	return port, nil
}
