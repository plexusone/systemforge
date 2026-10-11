# Casbin Removal Tasks

> **Status**: ✅ Complete
>
> Remove Casbin authorization provider from SystemForge now that SpiceDB is fully implemented.

## Overview

Casbin was the original authorization backend for SystemForge. With SpiceDB now fully integrated (including identity lifecycle sync), Casbin can be removed to simplify the codebase.

## Tasks

### 1. Remove Casbin Code

- [x] Delete `authz/casbin/provider.go`
- [x] Delete `authz/casbin/provider_conformance_test.go`
- [x] Delete `authz/casbin/` directory

### 2. Remove Dependencies

- [x] Remove `github.com/casbin/casbin/v2` from go.mod
- [x] Run `go mod tidy` to clean up transitive dependencies

### 3. Update Documentation

- [x] Update `authz/authorizer.go` comment (remove Casbin mention)
- [x] Update `README.md` (remove Casbin from features list)
- [x] Update any other docs referencing Casbin

### 4. Verify Build

- [x] Run `go build ./...`
- [x] Run `go test ./...`
- [x] Run `golangci-lint run`

## Verification

```bash
# Ensure no Casbin references remain
grep -r "casbin" --include="*.go" .
grep -r "casbin" go.mod go.sum

# Build and test
go build ./...
go test ./...
```

## Notes

- All Casbin code is isolated in `authz/casbin/`
- No production code depends on Casbin directly
- All usage goes through `authz.Authorizer` interface
- SpiceDB and Simple providers remain as alternatives
