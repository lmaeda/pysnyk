import abc
import json
from typing import Any, Dict, List

from deprecation import deprecated  # type: ignore

from .errors import SnykError, SnykNotFoundError, SnykNotImplementedError
from .utils import snake_to_camel


class Manager(abc.ABC):
    """
    A base class for managers.

    Managers are responsible for providing an interface to a particular type of
    object in the Snyk API.
    """

    def __init__(self, klass, client, instance=None):
        self.klass = klass
        self.client = client
        self.instance = instance

    @abc.abstractmethod
    def all(self):
        pass  # pragma: no cover

    def get(self, id: str):
        try:
            return next(x for x in self.all() if x.id == id)
        except StopIteration:
            raise SnykNotFoundError

    def first(self):
        try:
            return self.all()[0]
        except IndexError:
            raise SnykNotFoundError

    def _filter_by_kwargs(self, data, **kwargs: Any):
        if kwargs:
            for key, value in kwargs.items():
                data = [x for x in data if getattr(x, key) == value]
        return data

    def filter(self, **kwargs: Any):
        return self._filter_by_kwargs(self.all(), **kwargs)

    @staticmethod
    def factory(klass, client, instance=None):
        """
        A factory for creating managers.

        This is used to ensure that the correct manager is used for a given class.
        """
        try:
            if isinstance(klass, str):
                key = klass
            else:
                key = klass.__name__
            manager = {
                "Project": ProjectManager,
                "Organization": OrganizationManager,
                "Member": MemberManager,
                "License": LicenseManager,
                "Dependency": DependencyManager,
                "Entitlement": EntitlementManager,
                "Setting": SettingManager,
                "Ignore": IgnoreManager,
                "JiraIssue": JiraIssueManager,
                "DependencyGraph": DependencyGraphManager,
                "IssueSet": IssueSetManager,
                "IssueSetAggregated": IssueSetAggregatedManager,
                "Integration": IntegrationManager,
                "IntegrationSetting": IntegrationSettingManager,
                "Tag": TagManager,
                "IssuePaths": IssuePathsManager,
                "Target": TargetsManager,
                "RestIssue": IssuesManager,
                "Group": GroupManager,
                "RestUser": UserManager,
                "Collection": CollectionManager,
                "ServiceAccount": ServiceAccountManager,
                "Environment": EnvironmentManager,
                "Invite": InviteManager,
                "App": AppManager,
                "AuditLog": AuditLogManager,
            }[key]
            return manager(klass, client, instance)
        except KeyError:
            raise SnykError


class ServiceAccountManager(Manager):
    """
    Manages Snyk Service Account objects for a given organization.
    """

    def all(self) -> List[Any]:
        """Returns a list of all service accounts for the organization."""
        if not self.instance:
            raise SnykError(
                "ServiceAccountManager must be initialized with an Organization"
            )

        path = f"orgs/{self.instance.id}/service_accounts"
        service_accounts_data = self.client.get_rest_pages(path)
        return [self.klass.from_dict(t) for t in service_accounts_data]

    def get(self, id: str) -> Any:
        """Returns a single service account by its ID."""
        if not self.instance:
            raise SnykError(
                "ServiceAccountManager must be initialized with an Organization"
            )

        path = f"orgs/{self.instance.id}/service_accounts/{id}"
        resp = self.client.get(path, rest=True)
        service_account_data = resp.json()["data"]
        return self.klass.from_dict(service_account_data)

    def create(self, name: str, role_id: str, auth_type: str) -> Any:
        """Creates a new service account."""
        if not self.instance:
            raise SnykError(
                "ServiceAccountManager must be initialized with an Organization"
            )

        payload = {
            "data": {
                "type": "service_account",
                "attributes": {
                    "name": name,
                    "role_id": role_id,
                    "auth_type": auth_type,
                },
            }
        }

        path = f"orgs/{self.instance.id}/service_accounts"
        resp = self.client.post(path, payload, rest=True)
        service_account_data = resp.json()["data"]
        return self.klass.from_dict(service_account_data)

    def delete(self, id: str) -> bool:
        """Deletes a service account by its ID."""
        if not self.instance:
            raise SnykError(
                "ServiceAccountManager must be initialized with an Organization"
            )

        path = f"orgs/{self.instance.id}/service_accounts/{id}"
        return bool(self.client.delete(path, rest=True))


class AppManager(Manager):
    """
    Manages Snyk App objects for a given organization.
    """

    def all(self) -> List[Any]:
        """Returns a list of all apps for the organization."""
        if not self.instance:
            raise SnykError("AppManager must be initialized with an Organization")

        path = f"orgs/{self.instance.id}/apps/creations"
        apps_data = self.client.get_rest_pages(path)
        return [self.klass.from_dict(t) for t in apps_data]

    def get(self, id: str) -> Any:
        """Returns a single app by its ID."""
        if not self.instance:
            raise SnykError("AppManager must be initialized with an Organization")

        path = f"orgs/{self.instance.id}/apps/creations/{id}"
        resp = self.client.get(path, rest=True)
        app_data = resp.json()["data"]
        return self.klass.from_dict(app_data)

    def create(self, name: str, redirect_uris: List[str], scopes: List[str]) -> Any:
        """Creates a new app."""
        if not self.instance:
            raise SnykError("AppManager must be initialized with an Organization")

        payload = {
            "data": {
                "type": "app",
                "attributes": {
                    "name": name,
                    "redirect_uris": redirect_uris,
                    "scopes": scopes,
                },
            }
        }

        path = f"orgs/{self.instance.id}/apps/creations"
        resp = self.client.post(path, payload, rest=True)
        app_data = resp.json()["data"]
        return self.klass.from_dict(app_data)

    def delete(self, id: str) -> bool:
        """Deletes an app by its ID."""
        if not self.instance:
            raise SnykError("AppManager must be initialized with an Organization")

        path = f"orgs/{self.instance.id}/apps/creations/{id}"
        return bool(self.client.delete(path, rest=True))


class InviteManager(Manager):
    """
    Manages Snyk Invite objects for a given organization.
    """

    def all(self) -> List[Any]:
        """Returns a list of all invites for the organization."""
        if not self.instance:
            raise SnykError("InviteManager must be initialized with an Organization")

        path = f"orgs/{self.instance.id}/invites"
        invites_data = self.client.get_rest_pages(path)
        return [self.klass.from_dict(t) for t in invites_data]

    def create(self, email: str, role: str) -> Any:
        """Creates a new invite."""
        if not self.instance:
            raise SnykError("InviteManager must be initialized with an Organization")

        payload = {
            "data": {
                "type": "invite",
                "attributes": {"email": email, "role": role},
            }
        }

        path = f"orgs/{self.instance.id}/invites"
        resp = self.client.post(path, payload, rest=True)
        invite_data = resp.json()["data"]
        return self.klass.from_dict(invite_data)

    def delete(self, id: str) -> bool:
        """Deletes an invite by its ID."""
        if not self.instance:
            raise SnykError("InviteManager must be initialized with an Organization")

        path = f"orgs/{self.instance.id}/invites/{id}"
        return bool(self.client.delete(path, rest=True))


class EnvironmentManager(Manager):
    """
    Manages Snyk Environment objects for a given organization.
    """

    def all(self) -> List[Any]:
        """Returns a list of all environments for the organization."""
        if not self.instance:
            raise SnykError(
                "EnvironmentManager must be initialized with an Organization"
            )

        path = f"orgs/{self.instance.id}/cloud/environments"
        environments_data = self.client.get_rest_pages(path)
        return [self.klass.from_dict(t) for t in environments_data]

    def get(self, id: str) -> Any:
        """Returns a single environment by its ID."""
        if not self.instance:
            raise SnykError(
                "EnvironmentManager must be initialized with an Organization"
            )

        path = f"orgs/{self.instance.id}/cloud/environments/{id}"
        resp = self.client.get(path, rest=True)
        environment_data = resp.json()["data"]
        return self.klass.from_dict(environment_data)

    def create(self, name: str, kind: str, options: dict) -> Any:
        """Creates a new environment."""
        if not self.instance:
            raise SnykError(
                "EnvironmentManager must be initialized with an Organization"
            )

        payload = {
            "data": {
                "type": "environment",
                "attributes": {"name": name, "kind": kind, "options": options},
            }
        }

        path = f"orgs/{self.instance.id}/cloud/environments"
        resp = self.client.post(path, payload, rest=True)
        environment_data = resp.json()["data"]
        return self.klass.from_dict(environment_data)

    def delete(self, id: str) -> bool:
        """Deletes an environment by its ID."""
        if not self.instance:
            raise SnykError(
                "EnvironmentManager must be initialized with an Organization"
            )

        path = f"orgs/{self.instance.id}/cloud/environments/{id}"
        return bool(self.client.delete(path, rest=True))

    def update(self, id: str, name: str, options: dict) -> Any:
        """Updates an environment."""
        if not self.instance:
            raise SnykError(
                "EnvironmentManager must be initialized with an Organization"
            )

        payload = {
            "data": {
                "type": "environment",
                "id": id,
                "attributes": {"name": name, "options": options},
            }
        }

        path = f"orgs/{self.instance.id}/cloud/environments/{id}"
        resp = self.client.patch(path, payload, rest=True)
        environment_data = resp.json()["data"]
        return self.klass.from_dict(environment_data)


class AuditLogManager(Manager):
    """
    Manages Snyk Audit Log objects for a given organization.
    """

    def all(self) -> List[Any]:
        """Returns a list of all audit log entries for the organization."""
        if not self.instance:
            raise SnykError("AuditLogManager must be initialized with an Organization")

        path = f"orgs/{self.instance.id}/audit_logs/search"
        audit_log_data = self.client.get_rest_pages(path)
        return [self.klass.from_dict(t) for t in audit_log_data]


class CollectionManager(Manager):
    """
    Manages Snyk Collection objects for a given organization.
    """

    def all(self) -> List[Any]:
        """Returns a list of all collections for the organization."""
        if not self.instance:
            raise SnykError(
                "CollectionManager must be initialized with an Organization"
            )

        path = f"orgs/{self.instance.id}/collections"
        collections_data = self.client.get_rest_pages(path)
        return [self.klass.from_dict(t) for t in collections_data]

    def get(self, id: str) -> Any:
        """Returns a single collection by its ID."""
        if not self.instance:
            raise SnykError(
                "CollectionManager must be initialized with an Organization"
            )

        path = f"orgs/{self.instance.id}/collections/{id}"
        resp = self.client.get(path, rest=True)
        collection_data = resp.json()["data"]
        return self.klass.from_dict(collection_data)

    def create(self, name: str) -> Any:
        """Creates a new collection."""
        if not self.instance:
            raise SnykError(
                "CollectionManager must be initialized with an Organization"
            )

        payload = {
            "data": {
                "type": "collection",
                "attributes": {"name": name},
            }
        }

        path = f"orgs/{self.instance.id}/collections"
        resp = self.client.post(path, payload, rest=True)
        collection_data = resp.json()["data"]
        return self.klass.from_dict(collection_data)


class UserManager(Manager):
    """
    Manages Snyk User objects.
    """

    def all(self):
        raise SnykNotImplementedError("Listing all users is not supported.")

    def get(self, id: str) -> Any:
        """Returns a single user by their ID."""
        resp = self.client.get(f"users/{id}", rest=True)
        user_data = resp.json()["data"]
        return self.klass.from_dict(user_data)


class GroupManager(Manager):
    """
    Manages Snyk Group objects.
    """

    def all(self) -> List[Any]:
        """Returns a list of all groups available to the user."""
        return [self.klass.from_dict(g) for g in self.client.get_rest_pages("groups")]

    def get(self, id: str) -> Any:
        """Returns a single group by its ID."""
        resp = self.client.get(f"groups/{id}", rest=True)
        group_data = resp.json()["data"]
        return self.klass.from_dict(group_data)


class IssuesManager(Manager):
    """
    Manages Snyk Issue objects for a given organization.

    This manager uses the Snyk REST API.
    """

    def all(self) -> List[Any]:
        """Returns a list of all issues for the organization."""
        if not self.instance:
            raise SnykError("IssuesManager must be initialized with an Organization")

        path = f"orgs/{self.instance.id}/issues"
        issues_data = self.client.get_rest_pages(path)
        return [self.klass.from_dict(t) for t in issues_data]

    def get(self, id: str) -> Any:
        """Returns a single issue by its ID."""
        if not self.instance:
            raise SnykError("IssuesManager must be initialized with an Organization")

        path = f"orgs/{self.instance.id}/issues/{id}"
        resp = self.client.get(path, rest=True)
        issue_data = resp.json()["data"]
        return self.klass.from_dict(issue_data)


class TargetsManager(Manager):
    """
    Manages Snyk Target objects for a given organization.

    Targets are the objects that Snyk scans, such as a repository or a container image.
    This manager uses the Snyk REST API.
    """

    def all(self) -> List[Any]:
        """Returns a list of all targets for the organization."""
        if not self.instance:
            raise SnykError("TargetsManager must be initialized with an Organization")

        path = f"orgs/{self.instance.id}/targets"
        targets_data = self.client.get_rest_pages(path)
        return [self.klass.from_dict(t) for t in targets_data]

    def get(self, id: str) -> Any:
        """Returns a single target by its ID."""
        if not self.instance:
            raise SnykError("TargetsManager must be initialized with an Organization")

        path = f"orgs/{self.instance.id}/targets/{id}"
        resp = self.client.get(path, rest=True)
        target_data = resp.json()["data"]
        return self.klass.from_dict(target_data)


class ServiceAccountManager(Manager):
    """
    Manages Snyk Service Account objects for a given organization.
    """

    def all(self) -> List[Any]:
        """Returns a list of all service accounts for the organization."""
        if not self.instance:
            raise SnykError(
                "ServiceAccountManager must be initialized with an Organization"
            )

        path = f"orgs/{self.instance.id}/service_accounts"
        service_accounts_data = self.client.get_rest_pages(path)
        return [self.klass.from_dict(t) for t in service_accounts_data]

    def get(self, id: str) -> Any:
        """Returns a single service account by its ID."""
        if not self.instance:
            raise SnykError(
                "ServiceAccountManager must be initialized with an Organization"
            )

        path = f"orgs/{self.instance.id}/service_accounts/{id}"
        resp = self.client.get(path, rest=True)
        service_account_data = resp.json()["data"]
        return self.klass.from_dict(service_account_data)

    def create(self, name: str, role_id: str, auth_type: str) -> Any:
        """Creates a new service account."""
        if not self.instance:
            raise SnykError(
                "ServiceAccountManager must be initialized with an Organization"
            )

        payload = {
            "data": {
                "type": "service_account",
                "attributes": {
                    "name": name,
                    "role_id": role_id,
                    "auth_type": auth_type,
                },
            }
        }

        path = f"orgs/{self.instance.id}/service_accounts"
        resp = self.client.post(path, payload, rest=True)
        service_account_data = resp.json()["data"]
        return self.klass.from_dict(service_account_data)

    def delete(self, id: str) -> bool:
        """Deletes a service account by its ID."""
        if not self.instance:
            raise SnykError(
                "ServiceAccountManager must be initialized with an Organization"
            )

        path = f"orgs/{self.instance.id}/service_accounts/{id}"
        return bool(self.client.delete(path, rest=True))


class AppManager(Manager):
    """
    Manages Snyk App objects for a given organization.
    """

    def all(self) -> List[Any]:
        """Returns a list of all apps for the organization."""
        if not self.instance:
            raise SnykError("AppManager must be initialized with an Organization")

        path = f"orgs/{self.instance.id}/apps/creations"
        apps_data = self.client.get_rest_pages(path)
        return [self.klass.from_dict(t) for t in apps_data]

    def get(self, id: str) -> Any:
        """Returns a single app by its ID."""
        if not self.instance:
            raise SnykError("AppManager must be initialized with an Organization")

        path = f"orgs/{self.instance.id}/apps/creations/{id}"
        resp = self.client.get(path, rest=True)
        app_data = resp.json()["data"]
        return self.klass.from_dict(app_data)

    def create(self, name: str, redirect_uris: List[str], scopes: List[str]) -> Any:
        """Creates a new app."""
        if not self.instance:
            raise SnykError("AppManager must be initialized with an Organization")

        payload = {
            "data": {
                "type": "app",
                "attributes": {
                    "name": name,
                    "redirect_uris": redirect_uris,
                    "scopes": scopes,
                },
            }
        }

        path = f"orgs/{self.instance.id}/apps/creations"
        resp = self.client.post(path, payload, rest=True)
        app_data = resp.json()["data"]
        return self.klass.from_dict(app_data)

    def delete(self, id: str) -> bool:
        """Deletes an app by its ID."""
        if not self.instance:
            raise SnykError("AppManager must be initialized with an Organization")

        path = f"orgs/{self.instance.id}/apps/creations/{id}"
        return bool(self.client.delete(path, rest=True))


class InviteManager(Manager):
    """
    Manages Snyk Invite objects for a given organization.
    """

    def all(self) -> List[Any]:
        """Returns a list of all invites for the organization."""
        if not self.instance:
            raise SnykError("InviteManager must be initialized with an Organization")

        path = f"orgs/{self.instance.id}/invites"
        invites_data = self.client.get_rest_pages(path)
        return [self.klass.from_dict(t) for t in invites_data]

    def create(self, email: str, role: str) -> Any:
        """Creates a new invite."""
        if not self.instance:
            raise SnykError("InviteManager must be initialized with an Organization")

        payload = {
            "data": {
                "type": "invite",
                "attributes": {"email": email, "role": role},
            }
        }

        path = f"orgs/{self.instance.id}/invites"
        resp = self.client.post(path, payload, rest=True)
        invite_data = resp.json()["data"]
        return self.klass.from_dict(invite_data)

    def delete(self, id: str) -> bool:
        """Deletes an invite by its ID."""
        if not self.instance:
            raise SnykError("InviteManager must be initialized with an Organization")

        path = f"orgs/{self.instance.id}/invites/{id}"
        return bool(self.client.delete(path, rest=True))


class EnvironmentManager(Manager):
    """
    Manages Snyk Environment objects for a given organization.
    """

    def all(self) -> List[Any]:
        """Returns a list of all environments for the organization."""
        if not self.instance:
            raise SnykError(
                "EnvironmentManager must be initialized with an Organization"
            )

        path = f"orgs/{self.instance.id}/cloud/environments"
        environments_data = self.client.get_rest_pages(path)
        return [self.klass.from_dict(t) for t in environments_data]

    def get(self, id: str) -> Any:
        """Returns a single environment by its ID."""
        if not self.instance:
            raise SnykError(
                "EnvironmentManager must be initialized with an Organization"
            )

        path = f"orgs/{self.instance.id}/cloud/environments/{id}"
        resp = self.client.get(path, rest=True)
        environment_data = resp.json()["data"]
        return self.klass.from_dict(environment_data)

    def create(self, name: str, kind: str, options: dict) -> Any:
        """Creates a new environment."""
        if not self.instance:
            raise SnykError(
                "EnvironmentManager must be initialized with an Organization"
            )

        payload = {
            "data": {
                "type": "environment",
                "attributes": {"name": name, "kind": kind, "options": options},
            }
        }

        path = f"orgs/{self.instance.id}/cloud/environments"
        resp = self.client.post(path, payload, rest=True)
        environment_data = resp.json()["data"]
        return self.klass.from_dict(environment_data)

    def delete(self, id: str) -> bool:
        """Deletes an environment by its ID."""
        if not self.instance:
            raise SnykError(
                "EnvironmentManager must be initialized with an Organization"
            )

        path = f"orgs/{self.instance.id}/cloud/environments/{id}"
        return bool(self.client.delete(path, rest=True))

    def update(self, id: str, name: str, options: dict) -> Any:
        """Updates an environment."""
        if not self.instance:
            raise SnykError(
                "EnvironmentManager must be initialized with an Organization"
            )

        payload = {
            "data": {
                "type": "environment",
                "id": id,
                "attributes": {"name": name, "options": options},
            }
        }

        path = f"orgs/{self.instance.id}/cloud/environments/{id}"
        resp = self.client.patch(path, payload, rest=True)
        environment_data = resp.json()["data"]
        return self.klass.from_dict(environment_data)


class AuditLogManager(Manager):
    """
    Manages Snyk Audit Log objects for a given organization.
    """

    def all(self) -> List[Any]:
        """Returns a list of all audit log entries for the organization."""
        if not self.instance:
            raise SnykError("AuditLogManager must be initialized with an Organization")

        path = f"orgs/{self.instance.id}/audit_logs/search"
        audit_log_data = self.client.get_rest_pages(path)
        return [self.klass.from_dict(t) for t in audit_log_data]


class CollectionManager(Manager):
    """
    Manages Snyk Collection objects for a given organization.
    """

    def all(self) -> List[Any]:
        """Returns a list of all collections for the organization."""
        if not self.instance:
            raise SnykError(
                "CollectionManager must be initialized with an Organization"
            )

        path = f"orgs/{self.instance.id}/collections"
        collections_data = self.client.get_rest_pages(path)
        return [self.klass.from_dict(t) for t in collections_data]

    def get(self, id: str) -> Any:
        """Returns a single collection by its ID."""
        if not self.instance:
            raise SnykError(
                "CollectionManager must be initialized with an Organization"
            )

        path = f"orgs/{self.instance.id}/collections/{id}"
        resp = self.client.get(path, rest=True)
        collection_data = resp.json()["data"]
        return self.klass.from_dict(collection_data)

    def create(self, name: str) -> Any:
        """Creates a new collection."""
        if not self.instance:
            raise SnykError(
                "CollectionManager must be initialized with an Organization"
            )

        payload = {
            "data": {
                "type": "collection",
                "attributes": {"name": name},
            }
        }

        path = f"orgs/{self.instance.id}/collections"
        resp = self.client.post(path, payload, rest=True)
        collection_data = resp.json()["data"]
        return self.klass.from_dict(collection_data)


class UserManager(Manager):
    """
    Manages Snyk User objects.
    """

    def all(self):
        raise SnykNotImplementedError("Listing all users is not supported.")

    def get(self, id: str) -> Any:
        """Returns a single user by their ID."""
        resp = self.client.get(f"users/{id}", rest=True)
        user_data = resp.json()["data"]
        return self.klass.from_dict(user_data)


class GroupManager(Manager):
    """
    Manages Snyk Group objects.
    """

    def all(self) -> List[Any]:
        """Returns a list of all groups available to the user."""
        return [self.klass.from_dict(g) for g in self.client.get_rest_pages("groups")]

    def get(self, id: str) -> Any:
        """Returns a single group by its ID."""
        resp = self.client.get(f"groups/{id}", rest=True)
        group_data = resp.json()["data"]
        return self.klass.from_dict(group_data)


class IssuesManager(Manager):
    """
    Manages Snyk Issue objects for a given organization.

    This manager uses the Snyk REST API.
    """

    def all(self) -> List[Any]:
        """Returns a list of all issues for the organization."""
        if not self.instance:
            raise SnykError("IssuesManager must be initialized with an Organization")

        path = f"orgs/{self.instance.id}/issues"
        issues_data = self.client.get_rest_pages(path)
        return [self.klass.from_dict(t) for t in issues_data]

    def get(self, id: str) -> Any:
        """Returns a single issue by its ID."""
        if not self.instance:
            raise SnykError("IssuesManager must be initialized with an Organization")

        path = f"orgs/{self.instance.id}/issues/{id}"
        resp = self.client.get(path, rest=True)
        issue_data = resp.json()["data"]
        return self.klass.from_dict(issue_data)


class TargetsManager(Manager):
    """
    Manages Snyk Target objects for a given organization.

    Targets are the objects that Snyk scans, such as a repository or a container image.
    This manager uses the Snyk REST API.
    """

    def all(self) -> List[Any]:
        """Returns a list of all targets for the organization."""
        if not self.instance:
            raise SnykError("TargetsManager must be initialized with an Organization")

        path = f"orgs/{self.instance.id}/targets"
        targets_data = self.client.get_rest_pages(path)
        return [self.klass.from_dict(t) for t in targets_data]

    def get(self, id: str) -> Any:
        """Returns a single target by its ID."""
        if not self.instance:
            raise SnykError("TargetsManager must be initialized with an Organization")

        path = f"orgs/{self.instance.id}/targets/{id}"
        resp = self.client.get(path, rest=True)
        target_data = resp.json()["data"]
        return self.klass.from_dict(target_data)


class DictManager(Manager):
    @abc.abstractmethod
    def all(self) -> Dict[str, Any]:
        pass  # pragma: no cover

    def get(self, id: str):
        try:
            return self.all()[id]
        except KeyError:
            raise SnykNotFoundError

    def filter(self, **kwargs: Any):
        raise SnykNotImplementedError

    def first(self):
        try:
            return next(iter(self.all().items()))
        except StopIteration:
            raise SnykNotFoundError


class SingletonManager(Manager):
    @abc.abstractmethod
    def all(self) -> Any:
        pass  # pragma: no cover

    def first(self):
        raise SnykNotImplementedError  # pragma: no cover

    def get(self, id: str):
        raise SnykNotImplementedError  # pragma: no cover

    def filter(self, **kwargs: Any):
        raise SnykNotImplementedError  # pragma: no cover


class OrganizationManager(Manager):
    def all(self):
        resp = self.client.get("orgs")
        orgs = []
        if "orgs" in resp.json():
            for org_data in resp.json()["orgs"]:
                orgs.append(self.klass.from_dict(org_data))
        for org in orgs:
            org.client = self.client
        return orgs


class TagManager(Manager):
    def all(self):
        return self.instance._tags

    def add(self, key, value) -> bool:
        tag = {"key": key, "value": value}
        path = "org/%s/project/%s/tags" % (
            self.instance.organization.id,
            self.instance.id,
        )
        return bool(self.client.post(path, tag))

    def delete(self, key, value) -> bool:
        tag = {"key": key, "value": value}
        path = "org/%s/project/%s/tags/remove" % (
            self.instance.organization.id,
            self.instance.id,
        )
        return bool(self.client.post(path, tag))


class ProjectManager(Manager):
    def _rest_to_v1_response_format(self, project: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transforms a project dictionary from the Snyk REST API format to the
        legacy Snyk API v1 format.

        This is a compatibility layer to ensure that consumers of the Project model
        get a consistent data structure, regardless of which API version the data
        was fetched from.
        """
        attributes = project.get("attributes", {})
        settings = attributes.get("settings", {})
        recurring_tests = settings.get("recurring_tests", {})
        issue_counts = project.get("meta", {}).get("latest_issue_counts", {})
        remote_repo_url = (
            project.get("relationships", {})
            .get("target", {})
            .get("data", {})
            .get("attributes", {})
            .get("url")
        )
        image_cluster = (
            project.get("relationships", {})
            .get("target", {})
            .get("data", {})
            .get("meta", {})
            .get("integration_data", {})
            .get("cluster")
        )
        return {
            "name": attributes.get("name"),
            "id": project.get("id"),
            "created": attributes.get("created"),
            "origin": attributes.get("origin"),
            "type": attributes.get("type"),
            "readOnly": attributes.get("read_only"),
            "testFrequency": recurring_tests.get("frequency"),
            "lastTestedDate": issue_counts.get("updated_at"),
            "isMonitored": True if attributes.get("status") == "active" else False,
            "issueCountsBySeverity": {
                "low": issue_counts.get("low", 0),
                "medium": issue_counts.get("medium", 0),
                "high": issue_counts.get("high", 0),
                "critical": issue_counts.get("critical", 0),
            },
            "targetReference": attributes.get("target_reference"),
            "branch": attributes.get("target_reference"),
            "remoteRepoUrl": remote_repo_url,
            "imageCluster": image_cluster,
            "_tags": attributes.get("tags", []),
            "importingUserId": project.get("relationships", {})
            .get("importer", {})
            .get("data", {})
            .get("id"),
            "owningUserId": project.get("relationships", {})
            .get("owner", {})
            .get("data", {})
            .get("id"),
        }

    def _query(self, tags: List[Dict[str, str]] = [], next_url: str = None):
        projects = []
        params: dict = {"limit": 100}
        if self.instance:
            path = "/orgs/%s/projects" % self.instance.id if not next_url else next_url

            # Append to params if we've got tags
            if tags:
                for tag in tags:
                    if "key" not in tag or "value" not in tag or len(tag.keys()) != 2:
                        raise SnykError("Each tag must contain only a key and a value")
                data = [f'{d["key"]}:{d["value"]}' for d in tags]
                params["tags"] = ",".join(data)

            # Append the issue count param to the params if this is the first page
            if not next_url:
                params["meta.latest_issue_counts"] = "true"
                params["expand"] = "target"

            # And lastly, make the API call
            if next_url:
                resp = self.client.get(next_url, params, rest=True)
            else:
                resp = self.client.get(path, params, rest=True)

            if "data" in resp.json():
                # Process projects in current response
                for response_data in resp.json()["data"]:
                    project_data = self._rest_to_v1_response_format(response_data)
                    project_data["organization"] = self.instance.to_dict()
                    try:
                        project_data["attributes"]["_tags"] = project_data[
                            "attributes"
                        ]["tags"]
                        del project_data["attributes"]["tags"]
                    except KeyError:
                        pass
                    if not project_data.get("totalDependencies"):
                        project_data["totalDependencies"] = 0
                    projects.append(self.klass.from_dict(project_data))

                # If we have another page, then process this page too
                if "next" in resp.json().get("links", {}):
                    next_url = resp.json().get("links", {})["next"]
                    projects.extend(self._query(tags, next_url))

            for x in projects:
                x.organization = self.instance
        else:
            for org in self.client.organizations.all():
                projects.extend(org.projects.all())
        return projects

    def all(self):
        return self._query()

    def filter(self, tags: List[Dict[str, str]] = [], **kwargs: Any):
        if tags:
            return self._filter_by_kwargs(self._query(tags), **kwargs)
        else:
            return super().filter(**kwargs)

    def get(self, id: str):
        if self.instance:
            path = "org/%s/project/%s" % (self.instance.id, id)
            resp = self.client.get(path)
            project_data = resp.json()
            project_data["organization"] = self.instance.to_dict()
            # We move tags to _tags as a cache, to avoid the need for additional requests
            # when working with tags. We want tags to be the manager
            try:
                project_data["_tags"] = project_data["tags"]
                del project_data["tags"]
            except KeyError:
                pass
            if project_data.get("totalDependencies") is None:
                project_data["totalDependencies"] = 0
            project_klass = self.klass.from_dict(project_data)
            project_klass.organization = self.instance
            return project_klass
        else:
            return super().get(id)


class MemberManager(Manager):
    def all(self):
        path = "org/%s/members" % self.instance.id
        resp = self.client.get(path)
        members = []
        for member_data in resp.json():
            members.append(self.klass.from_dict(member_data))
        return members


class LicenseManager(Manager):
    def all(self):
        if hasattr(self.instance, "organization"):
            path = "org/%s/licenses" % self.instance.organization.id
            post_body = {"filters": {"projects": [self.instance.id]}}
        else:
            path = "org/%s/licenses" % self.instance.id
            post_body: Dict[str, Dict[str, List[str]]] = {"filters": {}}

        resp = self.client.post(path, post_body)
        license_data = resp.json()
        licenses = []
        if "results" in license_data:
            for license in license_data["results"]:
                licenses.append(self.klass.from_dict(license))
        return licenses


class DependencyManager(Manager):
    def all(self, page: int = 1):
        results_per_page = 1000
        if hasattr(self.instance, "organization"):
            org_id = self.instance.organization.id
            post_body = {"filters": {"projects": [self.instance.id]}}
        else:
            org_id = self.instance.id
            post_body = {"filters": {}}

        path = "org/%s/dependencies?sortBy=dependency&order=asc&page=%s&perPage=%s" % (
            org_id,
            page,
            results_per_page,
        )

        resp = self.client.post(path, post_body)
        dependency_data = resp.json()

        total = dependency_data[
            "total"
        ]  # contains the total number of results (for pagination use)

        results = [self.klass.from_dict(item) for item in dependency_data["results"]]

        if total > (page * results_per_page):
            next_results = self.all(page + 1)
            results.extend(next_results)

        return results


class EntitlementManager(DictManager):
    def all(self) -> Dict[str, bool]:
        path = "org/%s/entitlements" % self.instance.id
        resp = self.client.get(path)
        return resp.json()


class SettingManager(DictManager):
    def all(self) -> Dict[str, Any]:
        path = "org/%s/project/%s/settings" % (
            self.instance.organization.id,
            self.instance.id,
        )
        resp = self.client.get(path)
        return resp.json()

    def update(self, **kwargs: bool) -> bool:
        path = "org/%s/project/%s/settings" % (
            self.instance.organization.id,
            self.instance.id,
        )
        post_body = {}

        settings = [
            "auto_dep_upgrade_enabled",
            "auto_dep_upgrade_ignored_dependencies",
            "auto_dep_upgrade_min_age",
            "auto_dep_upgrade_limit",
            "pull_request_fail_on_any_vulns",
            "pull_request_fail_only_for_high_severity",
            "pull_request_test_enabled",
            "pull_request_assignment",
            "pull_request_inheritance",
            "pull_request_fail_only_for_issues_with_fix",
            "auto_remediation_prs",
        ]

        for setting in settings:
            if setting in kwargs:
                post_body[snake_to_camel(setting)] = kwargs[setting]

        return bool(self.client.put(path, post_body))


class IgnoreManager(DictManager):
    def all(self) -> Dict[str, List[object]]:
        path = "org/%s/project/%s/ignores" % (
            self.instance.organization.id,
            self.instance.id,
        )
        resp = self.client.get(path)
        return resp.json()


class JiraIssueManager(DictManager):
    def all(self) -> Dict[str, List[object]]:
        path = "org/%s/project/%s/jira-issues" % (
            self.instance.organization.id,
            self.instance.id,
        )
        resp = self.client.get(path)
        return resp.json()

    def create(self, issue_id: str, fields: Any) -> Dict[str, str]:
        path = "org/%s/project/%s/issue/%s/jira-issue" % (
            self.instance.organization.id,
            self.instance.id,
            issue_id,
        )
        post_body = {"fields": fields}
        resp = self.client.post(path, post_body)
        response_data = resp.json()
        # The response we get is not following the schema as specified by the api
        # https://snyk.docs.apiary.io/#reference/projects/project-jira-issues-/create-jira-issue
        if (
            issue_id in response_data
            and len(response_data[issue_id]) > 0
            and "jiraIssue" in response_data[issue_id][0]
        ):
            return response_data[issue_id][0]["jiraIssue"]
        raise SnykError


class IntegrationManager(Manager):
    def all(self):
        path = "org/%s/integrations" % self.instance.id
        resp = self.client.get(path)
        integrations = []
        integrations_data = [{"name": x, "id": resp.json()[x]} for x in resp.json()]
        for data in integrations_data:
            integrations.append(self.klass.from_dict(data))
        for integration in integrations:
            integration.organization = self.instance
        return integrations


class IntegrationSettingManager(DictManager):
    def all(self):
        path = "org/%s/integrations/%s/settings" % (
            self.instance.organization.id,
            self.instance.id,
        )
        resp = self.client.get(path)
        return resp.json()


class DependencyGraphManager(SingletonManager):
    def all(self) -> Any:
        path = "org/%s/project/%s/dep-graph" % (
            self.instance.organization.id,
            self.instance.id,
        )
        resp = self.client.get(path)
        dependency_data = resp.json()
        if "depGraph" in dependency_data:
            return self.klass.from_dict(dependency_data["depGraph"])
        raise SnykError


@deprecated("API has been removed, use IssueSetAggregatedManager instead")
class IssueSetManager(SingletonManager):
    def _convert_reserved_words(self, data):
        for key in ["vulnerabilities", "licenses"]:
            if "issues" in data and key in data["issues"]:
                for i, vuln in enumerate(data["issues"][key]):
                    if "from" in vuln:
                        data["issues"][key][i]["fromPackages"] = data["issues"][key][
                            i
                        ].pop("from")
        return data

    def all(self) -> Any:
        return self.filter()

    def filter(self, **kwargs: Any):
        path = "org/%s/project/%s/issues" % (
            self.instance.organization.id,
            self.instance.id,
        )
        filters = {
            "severities": ["critical", "high", "medium", "low"],
            "types": ["vuln", "license"],
            "ignored": False,
            "patched": False,
        }
        for filter_name in filters.keys():
            if kwargs.get(filter_name):
                filters[filter_name] = kwargs[filter_name]
        post_body = {"filters": filters}
        resp = self.client.post(path, post_body)
        return self.klass.from_dict(self._convert_reserved_words(resp.json()))


class IssueSetAggregatedManager(SingletonManager):
    def all(self) -> Any:
        return self.filter()

    def filter(self, **kwargs: Any):
        path = "org/%s/project/%s/aggregated-issues" % (
            self.instance.organization.id,
            self.instance.id,
        )
        default_filters = {
            "severities": ["critical", "high", "medium", "low"],
            "exploitMaturity": [
                "mature",
                "proof-of-concept",
                "no-known-exploit",
                "no-data",
            ],
            "types": ["vuln", "license"],
            "priority": {"score": {"min": 0, "max": 1000}},
        }

        post_body = {"filters": default_filters}

        all_filters = list(default_filters.keys()) + ["ignored", "patched"]
        for filter_name in all_filters:
            if filter_name in kwargs.keys():
                post_body["filters"][filter_name] = kwargs[filter_name]

        for optional_field in ["includeDescription", "includeIntroducedThrough"]:
            if optional_field in kwargs.keys():
                post_body[optional_field] = kwargs[optional_field]

        resp = self.client.post(path, post_body)
        return self.klass.from_dict(resp.json())


class IssuePathsManager(SingletonManager):
    def all(self):
        path = "org/%s/project/%s/issue/%s/paths" % (
            self.instance.organization_id,
            self.instance.project_id,
            self.instance.id,
        )
        resp = self.client.get(path)
        return self.klass.from_dict(resp.json())
