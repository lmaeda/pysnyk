import os
import re

import pytest  # type: ignore

from snyk import SnykClient
from snyk.__version__ import __version__
from snyk.errors import SnykError, SnykNotFoundError
from snyk.models import Organization, Project
from snyk.utils import load_test_data

TEST_DATA = os.path.join(os.path.dirname(__file__), "test_data")

REST_ORG = "39ddc762-b1b9-41ce-ab42-defbe4575bd6"
REST_URL = "https://api.snyk.io/rest"
REST_VERSION = "2022-02-16~experimental"

V3_ORG = "39ddc762-b1b9-41ce-ab42-defbe4575bd6"
V3_URL = "https://api.snyk.io/v3"
V3_VERSION = "2022-02-16~experimental"


class TestSnykClient(object):
    @pytest.fixture
    def client(self):
        return SnykClient("token")

    def test_default_api_url(self, client):
        assert client.api_url == "https://api.snyk.io/v1"

    def test_overriding_api_url(self):
        url = "https://api.notsnyk.io/v1"
        client = SnykClient("token", url)
        assert client.api_url == url

    def test_token_added_to_headers(self, client):
        assert client.api_headers["Authorization"] == "token token"

    def test_user_agent_added_to_headers(self, client):
        assert client.api_headers["User-Agent"] == "pysnyk/%s" % __version__

    def test_overriding_user_agent(self):
        ua = "test"
        client = SnykClient("token", user_agent=ua)
        assert client.api_headers["User-Agent"] == ua

    def test_token_added_to_post_headers(self, client):
        assert client.api_post_headers["Authorization"] == "token token"

    def test_post_headers_use_correct_mimetype(self, client):
        assert client.api_post_headers["Content-Type"] == "application/json"

    def test_get_sends_request_to_snyk(self, requests_mock, client):
        requests_mock.get("https://api.snyk.io/v1/sample", text="pong")
        assert client.get("sample")

    def test_put_sends_request_to_snyk(self, requests_mock, client):
        requests_mock.put("https://api.snyk.io/v1/sample", text="pong")
        assert client.put("sample", {})

    def test_delete_sends_request_to_snyk(self, requests_mock, client):
        requests_mock.delete("https://api.snyk.io/v1/sample")
        assert client.delete("sample")

    def test_post_sends_request_to_snyk(self, requests_mock, client):
        requests_mock.post("https://api.snyk.io/v1/sample")
        assert client.post("sample", {})
        assert requests_mock.call_count == 1

    def test_post_raises_error(self, requests_mock, client):
        requests_mock.post("https://api.snyk.io/v1/sample", status_code=500, json={})
        with pytest.raises(SnykError):
            client.post("sample", {})
        assert requests_mock.call_count == 1

    def test_put_retries_and_raises_error(self, requests_mock, client):
        requests_mock.put("https://api.snyk.io/v1/sample", status_code=500, json={})
        client = SnykClient("token", tries=4, delay=0, backoff=2)
        with pytest.raises(SnykError):
            client.put("sample", {})
        assert requests_mock.call_count == 4

    def test_delete_retries_and_raises_error(self, requests_mock, client):
        requests_mock.delete("https://api.snyk.io/v1/sample", status_code=500, json={})
        client = SnykClient("token", tries=4, delay=0, backoff=2)
        with pytest.raises(SnykError):
            client.delete("sample")
        assert requests_mock.call_count == 4

    def test_get_retries_and_raises_error(self, requests_mock, client):
        requests_mock.get("https://api.snyk.io/v1/sample", status_code=500, json={})
        client = SnykClient("token", tries=4, delay=0, backoff=2)
        with pytest.raises(SnykError):
            client.get("sample")
        assert requests_mock.call_count == 4

    def test_post_retries_and_raises_error(self, requests_mock, client):
        requests_mock.post("https://api.snyk.io/v1/sample", status_code=500, json={})
        client = SnykClient("token", tries=4, delay=0, backoff=2)
        with pytest.raises(SnykError):
            client.post("sample", {})
        assert requests_mock.call_count == 4

    def test_put_raises_error(self, requests_mock, client):
        requests_mock.put("https://api.snyk.io/v1/sample", status_code=500, json={})
        with pytest.raises(SnykError):
            client.put("sample", {})
        assert requests_mock.call_count == 1

    def test_delete_raises_error(self, requests_mock, client):
        requests_mock.delete("https://api.snyk.io/v1/sample", status_code=500, json={})
        with pytest.raises(SnykError):
            client.delete("sample")
        assert requests_mock.call_count == 1

    def test_get_raises_error(self, requests_mock, client):
        requests_mock.get("https://api.snyk.io/v1/sample", status_code=500, json={})
        with pytest.raises(SnykError):
            client.get("sample")
        assert requests_mock.call_count == 1

    def test_empty_organizations(self, requests_mock, client):
        requests_mock.get("https://api.snyk.io/v1/orgs", json={})
        assert [] == client.organizations.all()

    @pytest.fixture
    def organizations(self):
        return load_test_data(TEST_DATA, "organizations")

    @pytest.fixture
    def projects(self):
        return load_test_data(TEST_DATA, "projects")

    def test_loads_organizations(self, requests_mock, client, organizations):
        requests_mock.get("https://api.snyk.io/v1/orgs", json=organizations)
        assert len(client.organizations.all()) == 2

    def test_first_organizations(self, requests_mock, client, organizations):
        requests_mock.get("https://api.snyk.io/v1/orgs", json=organizations)
        org = client.organizations.first()
        assert "defaultOrg" == org.name

    def test_first_organizations_on_empty(self, requests_mock, client):
        requests_mock.get("https://api.snyk.io/v1/orgs", json={})
        with pytest.raises(SnykNotFoundError):
            client.organizations.first()

    def test_filter_organizations(self, requests_mock, client, organizations):
        requests_mock.get("https://api.snyk.io/v1/orgs", json=organizations)
        assert 1 == len(client.organizations.filter(name="defaultOrg"))

    def test_filter_organizations_empty(self, requests_mock, client, organizations):
        requests_mock.get("https://api.snyk.io/v1/orgs", json=organizations)
        assert [] == client.organizations.filter(name="not present")

    def test_loads_organization(self, requests_mock, client, organizations):
        key = organizations["orgs"][0]["id"]
        requests_mock.get("https://api.snyk.io/v1/orgs", json=organizations)
        org = client.organizations.get(key)
        assert "defaultOrg" == org.name

    def test_non_existent_organization(self, requests_mock, client, organizations):
        requests_mock.get("https://api.snyk.io/v1/orgs", json=organizations)
        with pytest.raises(SnykNotFoundError):
            client.organizations.get("not-present")

    def test_organization_type(self, requests_mock, client, organizations):
        requests_mock.get("https://api.snyk.io/v1/orgs", json=organizations)
        assert all(type(x) is Organization for x in client.organizations.all())

    def test_organization_attributes(self, requests_mock, client, organizations):
        requests_mock.get("https://api.snyk.io/v1/orgs", json=organizations)
        assert client.organizations.first().name == "defaultOrg"

    def test_organization_load_group(self, requests_mock, client, organizations):
        requests_mock.get("https://api.snyk.io/v1/orgs", json=organizations)
        assert client.organizations.all()[1].group.name == "ACME Inc."

    def test_empty_projects(self, requests_mock, client, organizations):
        requests_mock.get("https://api.snyk.io/v1/orgs", json=organizations)
        matcher = re.compile("projects.*$")
        requests_mock.get(matcher, json={})
        assert [] == client.projects.all()

    def test_projects(self, requests_mock, client, organizations, projects):
        requests_mock.get("https://api.snyk.io/v1/orgs", json=organizations)
        matcher = re.compile("projects.*$")
        requests_mock.get(matcher, json=projects)
        assert len(client.projects.all()) == 2
        assert all(type(x) is Project for x in client.projects.all())

    def test_project(self, requests_mock, client, organizations, projects):
        requests_mock.get("https://api.snyk.io/v1/orgs", json=organizations)
        matcher = re.compile("projects.*$")
        requests_mock.get(matcher, json=projects)
        assert (
            "testing-new-name"
            == client.projects.get("f9fec29a-d288-40d9-a019-cedf825e6efb").name
        )

    def test_non_existent_project(self, requests_mock, client, organizations, projects):
        requests_mock.get("https://api.snyk.io/v1/orgs", json=organizations)
        matcher = re.compile("projects.*$")
        requests_mock.get(matcher, json=projects)
        with pytest.raises(SnykNotFoundError):
            client.projects.get("not-present")

    @pytest.fixture
    def rest_client(self):
        return SnykClient(
            "token", version="2022-02-16~experimental", url="https://api.snyk.io/rest"
        )

    @pytest.fixture
    def v3_client(self):
        return SnykClient("token", version="2024-10-15", url="https://api.snyk.io/v3")

    @pytest.fixture
    def v3_groups(self):
        return load_test_data(TEST_DATA, "v3_groups")

    @pytest.fixture
    def v3_targets_page1(self):
        return load_test_data(TEST_DATA, "v3_targets_page1")

    @pytest.fixture
    def v3_targets_page2(self):
        return load_test_data(TEST_DATA, "v3_targets_page2")

    @pytest.fixture
    def v3_targets_page3(self):
        return load_test_data(TEST_DATA, "v3_targets_page3")

    @pytest.fixture
    def rest_groups(self):
        return load_test_data(TEST_DATA, "rest_groups")

    @pytest.fixture
    def rest_group(self):
        return load_test_data(TEST_DATA, "rest_group")

    @pytest.fixture
    def rest_targets_page1(self):
        return load_test_data(TEST_DATA, "rest_targets_page1")

    @pytest.fixture
    def rest_targets_page2(self):
        return load_test_data(TEST_DATA, "rest_targets_page2")

    @pytest.fixture
    def rest_targets_page3(self):
        return load_test_data(TEST_DATA, "rest_targets_page3")

    def test_v3get(self, requests_mock, v3_client, v3_targets_page1):
        requests_mock.get(
            f"{V3_URL}/orgs/{V3_ORG}/targets?limit=10&version={V3_VERSION}",
            json=v3_targets_page1,
        )
        t_params = {"limit": 10}

        targets = v3_client.get(f"orgs/{V3_ORG}/targets", t_params).json()

        assert len(targets["data"]) == 10

    def test_get_v3_pages(
        self,
        requests_mock,
        v3_client,
        v3_targets_page1,
        v3_targets_page2,
        v3_targets_page3,
    ):
        requests_mock.get(
            f"{V3_URL}/orgs/{V3_ORG}/targets?limit=10&version={V3_VERSION}",
            json=v3_targets_page1,
        )
        requests_mock.get(
            f"{V3_URL}/orgs/{V3_ORG}/targets?limit=10&version={V3_VERSION}&excludeEmpty=true&starting_after=v1.eyJpZCI6IjMyODE4ODAifQ%3D%3D",
            json=v3_targets_page2,
        )
        requests_mock.get(
            f"{V3_URL}/orgs/{V3_ORG}/targets?limit=10&version={V3_VERSION}&excludeEmpty=true&starting_after=v1.eyJpZCI6IjI5MTk1NjgifQ%3D%3D",
            json=v3_targets_page3,
        )
        t_params = {"limit": 10}

        data = v3_client.get_v3_pages(f"orgs/{V3_ORG}/targets", t_params)

        assert len(data) == 30

    def test_rest_get(self, requests_mock, rest_client, rest_targets_page1):
        requests_mock.get(
            f"{REST_URL}/orgs/{REST_ORG}/targets?limit=10&version={REST_VERSION}",
            json=rest_targets_page1,
        )
        t_params = {"limit": 10}

        targets = rest_client.get(f"orgs/{REST_ORG}/targets", t_params).json()

        assert len(targets["data"]) == 10

    def test_get_rest_pages(
        self,
        requests_mock,
        rest_client,
        rest_targets_page1,
        rest_targets_page2,
        rest_targets_page3,
    ):
        requests_mock.get(
            f"{REST_URL}/orgs/{REST_ORG}/targets?version={REST_VERSION}&limit=10",
            json=rest_targets_page1,
        )
        requests_mock.get(
            f"{REST_URL}/orgs/{REST_ORG}/targets?version={REST_VERSION}&excludeEmpty=true&starting_after=v1.eyJpZCI6IjMyODE4ODAifQ%3D%3D&limit=10",
            json=rest_targets_page2,
        )
        requests_mock.get(
            f"{REST_URL}/orgs/{REST_ORG}/targets?version={REST_VERSION}&excludeEmpty=true&starting_after=v1.eyJpZCI6IjI5MTk1NjgifQ%3D%3D&limit=10",
            json=rest_targets_page3,
        )
        t_params = {"limit": 10}

        data = rest_client.get_rest_pages(f"orgs/{V3_ORG}/targets", t_params)

        assert len(data) == 30

    def test_rest_limit_deduplication(self, requests_mock, rest_client):
        requests_mock.get(
            f"{REST_URL}/orgs/{REST_ORG}/projects?limit=100&version={REST_VERSION}"
        )
        params = {"limit": 10}
        rest_client.get(f"orgs/{REST_ORG}/projects?limit=100", params)

    @pytest.fixture
    def rest_targets(self):
        return load_test_data(TEST_DATA, "rest_targets")

    @pytest.fixture
    def rest_target(self):
        return load_test_data(TEST_DATA, "rest_target")

    def test_organization_targets_all(
        self, requests_mock, client, organizations, rest_targets
    ):
        org_id = organizations["orgs"][0]["id"]
        requests_mock.get(f"https://api.snyk.io/v1/orgs", json=organizations)
        requests_mock.get(
            f"{REST_URL}/orgs/{org_id}/targets?version={REST_VERSION}",
            json=rest_targets,
        )
        org = client.organizations.first()
        targets = org.targets.all()
        assert len(targets) == 2
        assert targets[0].id == "e7a4c0a0-7e87-4917-803b-76958d485a45"

    def test_organization_targets_get(
        self, requests_mock, client, organizations, rest_target
    ):
        org_id = organizations["orgs"][0]["id"]
        target_id = rest_target["data"]["id"]
        requests_mock.get(f"https://api.snyk.io/v1/orgs", json=organizations)
        requests_mock.get(
            f"{REST_URL}/orgs/{org_id}/targets/{target_id}?version={REST_VERSION}",
            json=rest_target,
        )
        org = client.organizations.first()
        target = org.targets.get(target_id)
        assert target.id == target_id

    def test_post_rest(self, requests_mock, rest_client):
        requests_mock.post(f"{REST_URL}/sample?version={REST_VERSION}")
        assert rest_client.post("sample", {}, rest=True)

    def test_put_rest(self, requests_mock, rest_client):
        requests_mock.put(f"{REST_URL}/sample?version={REST_VERSION}")
        assert rest_client.put("sample", {}, rest=True)

    def test_delete_rest(self, requests_mock, rest_client):
        requests_mock.delete(f"{REST_URL}/sample?version={REST_VERSION}")
        assert rest_client.delete("sample", rest=True)

    def test_client_groups_get(self, requests_mock, rest_client, rest_group):
        group_id = rest_group["data"]["id"]
        requests_mock.get(
            f"{REST_URL}/groups/{group_id}?version={REST_VERSION}", json=rest_group
        )
        group = rest_client.groups.get(group_id)
        assert group.id == group_id
        assert group.attributes["name"] == "My Group"

    @pytest.fixture
    def rest_user(self):
        return load_test_data(TEST_DATA, "rest_user")

    def test_client_users_get(self, requests_mock, rest_client, rest_user):
        user_id = rest_user["data"]["id"]
        requests_mock.get(
            f"{REST_URL}/users/{user_id}?version={REST_VERSION}", json=rest_user
        )
        user = rest_client.users.get(user_id)
        assert user.id == user_id
        assert user.attributes["name"] == "Test User"

    @pytest.fixture
    def rest_self(self):
        return load_test_data(TEST_DATA, "rest_self")

    def test_client_me(self, requests_mock, rest_client, rest_self):
        requests_mock.get(f"{REST_URL}/self?version={REST_VERSION}", json=rest_self)
        me = rest_client.me
        assert me.id == "a1b2c3d4-e5f6-7890-1234-567890abcdef"
        assert me.attributes["name"] == "Current User"

    @pytest.fixture
    def rest_self(self):
        return load_test_data(TEST_DATA, "rest_self")

    def test_client_me(self, requests_mock, rest_client, rest_self):
        requests_mock.get(f"{REST_URL}/self?version={REST_VERSION}", json=rest_self)
        me = rest_client.me
        assert me.id == "a1b2c3d4-e5f6-7890-1234-567890abcdef"
        assert me.attributes["name"] == "Current User"

    @pytest.fixture
    def rest_members(self):
        return load_test_data(TEST_DATA, "rest_members")

    def test_organization_members_all(
        self, requests_mock, client, organizations, rest_members
    ):
        org_id = organizations["orgs"][0]["id"]
        requests_mock.get(f"https://api.snyk.io/v1/orgs", json=organizations)
        requests_mock.get(
            f"{REST_URL}/orgs/{org_id}/memberships?version={REST_VERSION}",
            json=rest_members,
        )
        org = client.organizations.first()
        members = org.members.all()
        assert len(members) == 1
        assert members[0].id == "a1b2c3d4-e5f6-7890-1234-567890abcdef"

    @pytest.fixture
    def rest_service_accounts(self):
        return load_test_data(TEST_DATA, "rest_service_accounts")

    @pytest.fixture
    def rest_service_account(self):
        return load_test_data(TEST_DATA, "rest_service_account")

    def test_organization_service_accounts_all(
        self, requests_mock, client, organizations, rest_service_accounts
    ):
        org_id = organizations["orgs"][0]["id"]
        requests_mock.get(f"https://api.snyk.io/v1/orgs", json=organizations)
        requests_mock.get(
            f"{REST_URL}/orgs/{org_id}/service_accounts?version={REST_VERSION}",
            json=rest_service_accounts,
        )
        org = client.organizations.first()
        service_accounts = org.service_accounts.all()
        assert len(service_accounts) == 1
        assert service_accounts[0].id == "a1b2c3d4-e5f6-7890-1234-567890abcdef"

    def test_organization_service_accounts_get(
        self, requests_mock, client, organizations, rest_service_account
    ):
        org_id = organizations["orgs"][0]["id"]
        service_account_id = rest_service_account["data"]["id"]
        requests_mock.get(f"https://api.snyk.io/v1/orgs", json=organizations)
        requests_mock.get(
            f"{REST_URL}/orgs/{org_id}/service_accounts/{service_account_id}?version={REST_VERSION}",
            json=rest_service_account,
        )
        org = client.organizations.first()
        service_account = org.service_accounts.get(service_account_id)
        assert service_account.id == service_account_id

    @pytest.fixture
    def rest_collections(self):
        return load_test_data(TEST_DATA, "rest_collections")

    @pytest.fixture
    def rest_collection(self):
        return load_test_data(TEST_DATA, "rest_collection")

    def test_organization_collections_all(
        self, requests_mock, client, organizations, rest_collections
    ):
        org_id = organizations["orgs"][0]["id"]
        requests_mock.get(f"https://api.snyk.io/v1/orgs", json=organizations)
        requests_mock.get(
            f"{REST_URL}/orgs/{org_id}/collections?version={REST_VERSION}",
            json=rest_collections,
        )
        org = client.organizations.first()
        collections = org.collections.all()
        assert len(collections) == 2
        assert collections[0].id == "f9fec29a-d288-40d9-a019-cedf825e6efb"

    def test_organization_collections_get(
        self, requests_mock, client, organizations, rest_collection
    ):
        org_id = organizations["orgs"][0]["id"]
        collection_id = rest_collection["data"]["id"]
        requests_mock.get(f"https://api.snyk.io/v1/orgs", json=organizations)
        requests_mock.get(
            f"{REST_URL}/orgs/{org_id}/collections/{collection_id}?version={REST_VERSION}",
            json=rest_collection,
        )
        org = client.organizations.first()
        collection = org.collections.get(collection_id)
        assert collection.id == collection_id

    def test_organization_collections_create(
        self, requests_mock, client, organizations, rest_collection
    ):
        org_id = organizations["orgs"][0]["id"]
        requests_mock.get(f"https://api.snyk.io/v1/orgs", json=organizations)
        requests_mock.post(
            f"{REST_URL}/orgs/{org_id}/collections?version={REST_VERSION}",
            json=rest_collection,
        )
        org = client.organizations.first()
        collection = org.collections.create("My Collection")
        assert collection.id == "f9fec29a-d288-40d9-a019-cedf825e6efb"

    @pytest.fixture
    def rest_service_accounts(self):
        return load_test_data(TEST_DATA, "rest_service_accounts")

    @pytest.fixture
    def rest_service_account(self):
        return load_test_data(TEST_DATA, "rest_service_account")

    def test_organization_service_accounts_all(
        self, requests_mock, client, organizations, rest_service_accounts
    ):
        org_id = organizations["orgs"][0]["id"]
        requests_mock.get(f"https://api.snyk.io/v1/orgs", json=organizations)
        requests_mock.get(
            f"{REST_URL}/orgs/{org_id}/service_accounts?version={REST_VERSION}",
            json=rest_service_accounts,
        )
        org = client.organizations.first()
        service_accounts = org.service_accounts.all()
        assert len(service_accounts) == 1
        assert service_accounts[0].id == "a8b5e6f0-8e9d-4c3a-9f8b-7d6c5b4a3a21"

    def test_organization_service_accounts_get(
        self, requests_mock, client, organizations, rest_service_account
    ):
        org_id = organizations["orgs"][0]["id"]
        service_account_id = rest_service_account["data"]["id"]
        requests_mock.get(f"https://api.snyk.io/v1/orgs", json=organizations)
        requests_mock.get(
            f"{REST_URL}/orgs/{org_id}/service_accounts/{service_account_id}?version={REST_VERSION}",
            json=rest_service_account,
        )
        org = client.organizations.first()
        service_account = org.service_accounts.get(service_account_id)
        assert service_account.id == service_account_id

    def test_organization_service_accounts_create(
        self, requests_mock, client, organizations, rest_service_account
    ):
        org_id = organizations["orgs"][0]["id"]
        requests_mock.get(f"https://api.snyk.io/v1/orgs", json=organizations)
        requests_mock.post(
            f"{REST_URL}/orgs/{org_id}/service_accounts?version={REST_VERSION}",
            json=rest_service_account,
        )
        org = client.organizations.first()
        service_account = org.service_accounts.create(
            "Test Service Account", "f9fec29a-d288-40d9-a019-cedf825e6efb", "api_key"
        )
        assert service_account.id == "a8b5e6f0-8e9d-4c3a-9f8b-7d6c5b4a3a21"

    def test_organization_service_accounts_delete(
        self, requests_mock, client, organizations, rest_service_account
    ):
        org_id = organizations["orgs"][0]["id"]
        service_account_id = rest_service_account["data"]["id"]
        requests_mock.get(f"https://api.snyk.io/v1/orgs", json=organizations)
        requests_mock.delete(
            f"{REST_URL}/orgs/{org_id}/service_accounts/{service_account_id}?version={REST_VERSION}",
        )
        org = client.organizations.first()
        assert org.service_accounts.delete(service_account_id)

    @pytest.fixture
    def rest_audit_logs(self):
        return load_test_data(TEST_DATA, "rest_audit_logs")

    def test_organization_audit_logs_all(
        self, requests_mock, client, organizations, rest_audit_logs
    ):
        org_id = organizations["orgs"][0]["id"]
        requests_mock.get(f"https://api.snyk.io/v1/orgs", json=organizations)
        requests_mock.get(
            f"{REST_URL}/orgs/{org_id}/audit_logs/search?version={REST_VERSION}",
            json=rest_audit_logs,
        )
        org = client.organizations.first()
        audit_logs = org.audit_logs.all()
        assert len(audit_logs) == 1
        assert audit_logs[0].id == "f9fec29a-d288-40d9-a019-cedf825e6efb"

    @pytest.fixture
    def rest_integrations(self):
        return load_test_data(TEST_DATA, "rest_integrations")

    def test_organization_integrations_all(
        self, requests_mock, client, organizations, rest_integrations
    ):
        org_id = organizations["orgs"][0]["id"]
        requests_mock.get(f"https://api.snyk.io/v1/orgs", json=organizations)
        requests_mock.get(
            f"{REST_URL}/orgs/{org_id}/integrations?version={client.version}",
            json=rest_integrations,
        )
        org = client.organizations.first()
        integrations = org.integrations.all()
        assert len(integrations) == 1
        assert integrations[0].id == "a8b5e6f0-8e9d-4c3a-9f8b-7d6c5b4a3a21"

    @pytest.fixture
    def rest_environments(self):
        return load_test_data(TEST_DATA, "rest_environments")

    @pytest.fixture
    def rest_environment(self):
        return load_test_data(TEST_DATA, "rest_environment")

    def test_organization_environments_all(
        self, requests_mock, client, organizations, rest_environments
    ):
        org_id = organizations["orgs"][0]["id"]
        requests_mock.get(f"https://api.snyk.io/v1/orgs", json=organizations)
        requests_mock.get(
            f"{REST_URL}/orgs/{org_id}/cloud/environments?version={REST_VERSION}",
            json=rest_environments,
        )
        org = client.organizations.first()
        environments = org.environments.all()
        assert len(environments) == 1
        assert environments[0].id == "a8b5e6f0-8e9d-4c3a-9f8b-7d6c5b4a3a21"

    def test_organization_environments_get(
        self, requests_mock, client, organizations, rest_environment
    ):
        org_id = organizations["orgs"][0]["id"]
        environment_id = rest_environment["data"]["id"]
        requests_mock.get(f"https://api.snyk.io/v1/orgs", json=organizations)
        requests_mock.get(
            f"{REST_URL}/orgs/{org_id}/cloud/environments/{environment_id}?version={REST_VERSION}",
            json=rest_environment,
        )
        org = client.organizations.first()
        environment = org.environments.get(environment_id)
        assert environment.id == environment_id

    @pytest.fixture
    def rest_invites(self):
        return load_test_data(TEST_DATA, "rest_invites")

    @pytest.fixture
    def rest_invite(self):
        return load_test_data(TEST_DATA, "rest_invite")

    def test_organization_invitations_all(
        self, requests_mock, client, organizations, rest_invites
    ):
        org_id = organizations["orgs"][0]["id"]
        requests_mock.get(f"https://api.snyk.io/v1/orgs", json=organizations)
        requests_mock.get(
            f"{REST_URL}/orgs/{org_id}/invites?version={REST_VERSION}",
            json=rest_invites,
        )
        org = client.organizations.first()
        invites = org.invitations.all()
        assert len(invites) == 1
        assert invites[0].id == "a8b5e6f0-8e9d-4c3a-9f8b-7d6c5b4a3a21"

    def test_organization_invitations_create(
        self, requests_mock, client, organizations, rest_invite
    ):
        org_id = organizations["orgs"][0]["id"]
        requests_mock.get(f"https://api.snyk.io/v1/orgs", json=organizations)
        requests_mock.post(
            f"{REST_URL}/orgs/{org_id}/invites?version={client.version}",
            json=rest_invite,
        )
        org = client.organizations.first()
        invite = org.invitations.create("test@snyk.io", "admin")
        assert invite.id == "a8b5e6f0-8e9d-4c3a-9f8b-7d6c5b4a3a21"

    def test_organization_invitations_delete(
        self, requests_mock, client, organizations, rest_invite
    ):
        org_id = organizations["orgs"][0]["id"]
        invite_id = rest_invite["data"]["id"]
        requests_mock.get(f"https://api.snyk.io/v1/orgs", json=organizations)
        requests_mock.delete(
            f"{REST_URL}/orgs/{org_id}/invites/{invite_id}?version={REST_VERSION}",
        )
        org = client.organizations.first()
        assert org.invitations.delete(invite_id)

    @pytest.fixture
    def rest_audit_logs(self):
        return load_test_data(TEST_DATA, "rest_audit_logs")

    def test_organization_audit_logs_all(
        self, requests_mock, client, organizations, rest_audit_logs
    ):
        org_id = organizations["orgs"][0]["id"]
        requests_mock.get(f"https://api.snyk.io/v1/orgs", json=organizations)
        requests_mock.get(
            f"{REST_URL}/orgs/{org_id}/audit_logs/search?version={client.version}",
            json=rest_audit_logs,
        )
        org = client.organizations.first()
        audit_logs = org.audit_logs.all()
        assert len(audit_logs) == 1
        assert audit_logs[0].id == "f9fec29a-d288-40d9-a019-cedf825e6efb"
