# SCIM 2.0 Implementation Tasks

## Completed Tasks

### 1. Ent Store Implementation
- [x] Create `identity/scim/store/ent.go` - Concrete Store implementation using Ent
- [x] Implement user operations (GetUserByID, ListUsers, CreateUser, UpdateUser, DeleteUser)
- [x] Implement group operations (GetGroupByID, ListGroups, CreateGroup, UpdateGroup, DeleteGroup)
- [x] Implement membership operations (GetGroupsForUser, GetMembersForGroup, AddMemberToGroup, RemoveMemberFromGroup)
- [x] Add filter-to-Ent predicate translation for ListUsers/ListGroups

### 2. Mapper Tests
- [x] Create `identity/scim/mapper/user_test.go` - Tests for User mapper
- [x] Create `identity/scim/mapper/group_test.go` - Tests for Group mapper
- [x] Create `identity/scim/mapper/extension_test.go` - Tests for Enterprise extension mapper

### 3. Integration Tests
- [x] Create `identity/scim/scim_test.go` - Integration tests with mock store
- [x] Test full CRUD workflows for Users
- [x] Test full CRUD workflows for Groups
- [x] Test filter queries
- [x] Test PATCH operations
- [x] Test bulk operations (endpoint accessibility)

### 4. Authorization Hook Implementation
- [x] Create `identity/scim/auth.go` - Authorization hook using SystemForge's permission system
- [x] Implement scope-based authorization (scim:users:read, scim:users:write, etc.)
- [x] Integrate with OAuth token scopes from context
- [x] Add role-based authorization hook as alternative
- [x] Add composite authorization hook for combining multiple hooks

### 5. Bulk Operations Fix
- [x] Fix JSON unmarshaling for bulk operation data (map[string]any → typed structs)
- [x] Add convertToUser, convertToGroup, convertToPatchRequest helper functions
- [x] Add comprehensive bulk operation tests (create user, create group, multiple operations, validation errors)

### 6. Filter Enhancements
- [x] Add ID filter support for users (id eq "uuid")
- [x] Add ID filter support for groups (id eq "uuid")
- [x] Add filter query tests to integration tests (userName, displayName, active, logical operators)

### 7. Attribute Filtering
- [x] Create `identity/scim/attributes.go` - Attribute filtering logic
- [x] Implement `attributes` query parameter support (include only specified attributes)
- [x] Implement `excludedAttributes` query parameter support (exclude specified attributes)
- [x] Apply attribute filtering to single resource and list responses
- [x] Always include required fields (schemas, id, meta) regardless of filtering

### 8. POST /.search Endpoint
- [x] Add `SearchRequest` type for search request body
- [x] Implement `UsersSearchEndpoint` for POST /Users/.search
- [x] Implement `GroupsSearchEndpoint` for POST /Groups/.search
- [x] Support filter, attributes, excludedAttributes, sortBy, sortOrder, startIndex, count in search body

### 9. BulkId Cross-References
- [x] Track bulkId → resourceID mappings during bulk processing
- [x] Resolve `bulkId:xxx` references in operation paths (e.g., /Groups/bulkId:group1)
- [x] Resolve `bulkId:xxx` references in operation data (e.g., member values)
- [x] Add extractResourceID helper to get created resource IDs

### 10. Password Operations
- [x] Create `identity/scim/password.go` - Password hasher interface and implementations
- [x] Implement BcryptHasher for secure password hashing
- [x] Add PasswordHasher to Provider with WithPasswordHasher option
- [x] Hash passwords on user creation
- [x] Hash passwords on PATCH operations
- [x] Never return password hashes in responses
- [x] Add password PATCH support in applyUserAddReplace
