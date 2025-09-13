# Snyk REST API Design Document

## 1. Introduction

This document outlines the design of the Snyk APIs used by the `pysnyk` client. The goal is to document the current state and identify areas for improvement.

The `pysnyk` client interacts with two distinct Snyk APIs:
- **Snyk API v1**: The legacy REST API, which is feature-rich and the primary target of the high-level managers in `pysnyk`.
- **Snyk REST API (JSON:API)**: The modern, versioned API that follows the JSON:API specification. Support in `pysnyk` is currently experimental and low-level.

## 2. Authentication

Authentication for both APIs is handled via a Snyk API token. The token is provided when initializing the `SnykClient`.

```python
import snyk
# For API v1
v1_client = snyk.SnykClient("<your-api-token>")

# For the newer REST API, a version and the REST URL must be provided
rest_client = snyk.SnykClient("<your-api-token>", version="2022-02-16~experimental", url="https://api.snyk.io/rest")
```

The client automatically includes the token in the `Authorization` header for all subsequent requests.

## 3. API Versions

### 3.1. Snyk API v1

The v1 API is the most established and widely used API in the `pysnyk` client.

- **Base URL**: `https://api.snyk.io/v1`
- **Design**: It follows a traditional RESTful design, with predictable resource URLs. `pysnyk` provides a high-level object-oriented abstraction on top of it using "Managers" and "Models".
- **Pagination**: Uses query parameters `page` and `perPage` for paginating through collections.

#### Key Resources (v1)

The client is structured around a hierarchy of objects, starting from the top-level client.

- **Organizations**: `client.organizations.all()`
  - **Projects**: `org.projects.all()`
    - **Dependencies**: `project.dependencies.all()`
    - **Vulnerabilities**: `project.vulnerabilities`
    - **Settings**: `project.settings.update(...)`
    - **Ignores**: `project.ignores.all()`
  - **Members**: `org.members.all()`
  - **Licenses**: `org.licenses.all()`
  - **Integrations**: `org.integrations.all()`
- **Users**: `client.users.all()`
- **Testing**: `org.test_python(...)`, `org.test_pipfile(...)`, etc.

### 3.2. Snyk REST API (JSON:API)

This is the modern, preferred API for new Snyk functionality.

- **Base URL**: `https://api.snyk.io/rest`
- **Design**: Adheres to the **JSON:API v1.0** specification. Responses are structured with `data`, `attributes`, `relationships`, and `links` objects.
- **Versioning**: API versioning is mandatory and specified via a query parameter, e.g., `?version=2024-05-13~experimental`. Versions are date-based and may include a stability tag (e.g., `experimental`, `beta`).
- **Pagination**: Uses a cursor-based model with `starting_after` and `ending_before` parameters in pagination links, which is more robust for large datasets. The `pysnyk` client provides a `get_rest_pages()` helper to abstract this.

#### Key Resources (REST API)

The `rest-spec.json` file defines a comprehensive set of resources. `pysnyk` currently only provides low-level `get()` and `post()` methods.

- **Orgs**: `/orgs/{org_id}`
- **Groups**: `/groups/{group_id}`
- **Users**: `/users/{user_id}`, `/orgs/{org_id}/users`
- **Targets**: `/orgs/{org_id}/targets` (equivalent to projects in some contexts)
- **Issues**: `/orgs/{org_id}/issues` (a unified endpoint for different issue types)
- **SBOMs**: `/orgs/{org_id}/sboms`
- **Cloud Resources**: `/orgs/{org_id}/cloud/resources`
- **Custom Base Images**: `/orgs/{org_id}/custom_base_images`

## 4. Proposed Improvements for `pysnyk`

Based on the current state, the following improvements could enhance the `pysnyk` library:

1.  **Unified Client**: Refactor `SnykClient` to handle both API versions transparently. The client could inspect the path or have dedicated methods that automatically route to the correct API (v1 or REST), removing the need for users to instantiate two separate clients.

2.  **High-Level REST API Managers**: Implement a manager and model system for the REST API, similar to the existing v1 implementation. This would provide a much more intuitive and Pythonic interface for interacting with new API features like `/issues`, `/targets`, and `/cloud/resources`.
    - *Example Goal*: `rest_client.orgs.get("org-id").targets.all()`

3.  **Automated Client Generation**: The presence of OpenAPI specification files (`v1_spec.yaml`, `rest-spec.json`) is a strong indicator that client code could be partially or fully generated. This would:
    - Ensure the client stays synchronized with the Snyk API.
    - Rapidly expand coverage of all available endpoints.
    - Reduce manual maintenance overhead.

4.  **Migrate to REST API**: Develop a roadmap to gradually migrate functionality from the v1 API to the newer REST API as endpoints become available and stable. This would future-proof the library and align it with Snyk's strategic direction. The design of the unified client (Proposal #1) would be critical for a smooth transition.
