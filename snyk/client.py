import logging
import urllib.parse
from typing import Any, List, Optional
from urllib.parse import parse_qs, urlparse

import requests
from retry.api import retry_call

from .__version__ import __version__
from .errors import SnykHTTPError, SnykNotImplementedError
from .managers import Manager
from .models import (
    App,
    AuditLog,
    Collection,
    Environment,
    Group,
    Invite,
    Organization,
    Project,
    RestUser,
    ServiceAccount,
)
from .utils import cleanup_path

logger = logging.getLogger(__name__)


class SnykClient(object):
    """
    A client for interacting with the Snyk API.

    This client handles authentication and provides methods for making requests
    to both the Snyk API v1 and the newer Snyk REST API.
    """

    API_URL = "https://api.snyk.io/v1"
    REST_API_URL = "https://api.snyk.io/rest"
    USER_AGENT = "pysnyk/%s" % __version__

    def __init__(
        self,
        token: str,
        url: Optional[str] = None,
        rest_api_url: Optional[str] = None,
        user_agent: Optional[str] = USER_AGENT,
        debug: bool = False,
        tries: int = 1,
        delay: int = 1,
        backoff: int = 2,
        verify: bool = True,
        version: Optional[str] = None,
    ):
        self.api_token = token
        self.api_url = url or self.API_URL
        self.rest_api_url = rest_api_url or self.REST_API_URL
        self.api_headers = {
            "Authorization": "token %s" % self.api_token,
            "User-Agent": user_agent,
        }
        self.api_post_headers = self.api_headers
        self.api_post_headers["Content-Type"] = "application/json"
        self.tries = tries
        self.backoff = backoff
        self.delay = delay
        self.verify = verify
        self.version = version

        # Ensure we don't have a trailing /
        if self.api_url[-1] == "/":
            self.api_url = self.api_url.rstrip("/")
        if self.rest_api_url[-1] == "/":
            self.rest_api_url = self.rest_api_url.rstrip("/")

        if debug:
            logging.basicConfig(level=logging.DEBUG)

    def request(
        self,
        method,
        url: str,
        headers: object,
        params: object = None,
        json: object = None,
    ) -> requests.Response:
        """
        A generic helper for making requests, used by the other methods.

        Includes the retry logic.
        """
        if params and json:
            resp = method(
                url, headers=headers, params=params, json=json, verify=self.verify
            )
        elif params and not json:
            resp = method(url, headers=headers, params=params, verify=self.verify)
        elif json and not params:
            resp = method(url, headers=headers, json=json, verify=self.verify)
        else:
            resp = method(url, headers=headers, verify=self.verify)

        if not resp or resp.status_code >= requests.codes.server_error:
            logger.warning(f"Retrying: {resp.text}")
            raise SnykHTTPError(resp)
        return resp

    def post(
        self, path: str, body: Any, headers: dict = {}, rest: bool = False
    ) -> requests.Response:
        """
        Makes a POST request to the Snyk API.

        :param path: The path for the API endpoint.
        :param body: The request body.
        :param headers: Additional headers for the request.
        :param rest: If True, targets the REST API. Otherwise, targets the v1 API.
        :return: A requests.Response object.
        """
        if rest:
            base_url = self.rest_api_url
            params = {}
            if self.version:
                params["version"] = self.version
            # REST API may use a different content type, which can be passed in via headers
            post_headers = self.api_post_headers.copy()
            fkwargs = {
                "json": body,
                "headers": {**post_headers, **headers},
                "params": params,
            }
        else:
            base_url = self.api_url
            fkwargs = {"json": body, "headers": {**self.api_post_headers, **headers}}

        url = f"{base_url}/{cleanup_path(path)}"
        logger.debug(f"POST: {url}")

        resp = retry_call(
            self.request,
            fargs=[requests.post, url],
            fkwargs=fkwargs,
            tries=self.tries,
            delay=self.delay,
            backoff=self.backoff,
            exceptions=SnykHTTPError,
            logger=logger,
        )

        if not resp.ok:
            logger.error(resp.text)
            raise SnykHTTPError(resp)

        return resp

    def put(
        self, path: str, body: Any, headers: dict = {}, rest: bool = False
    ) -> requests.Response:
        """
        Makes a PUT request to the Snyk API.

        :param path: The path for the API endpoint.
        :param body: The request body.
        :param headers: Additional headers for the request.
        :param rest: If True, targets the REST API. Otherwise, targets the v1 API.
        :return: A requests.Response object.
        """
        if rest:
            base_url = self.rest_api_url
            params = {}
            if self.version:
                params["version"] = self.version
            # REST API may use a different content type, which can be passed in via headers
            post_headers = self.api_post_headers.copy()
            fkwargs = {
                "json": body,
                "headers": {**post_headers, **headers},
                "params": params,
            }
        else:
            base_url = self.api_url
            fkwargs = {"json": body, "headers": {**self.api_post_headers, **headers}}

        url = f"{base_url}/{cleanup_path(path)}"
        logger.debug(f"PUT: {url}")

        resp = retry_call(
            self.request,
            fargs=[requests.put, url],
            fkwargs=fkwargs,
            tries=self.tries,
            delay=self.delay,
            backoff=self.backoff,
            logger=logger,
        )
        if not resp.ok:
            logger.error(resp.text)
            raise SnykHTTPError(resp)

        return resp

    def get(
        self,
        path: str,
        params: dict = None,
        version: str = None,
        rest: bool = False,
    ) -> requests.Response:
        """
        Makes a GET request to the Snyk API.

        :param path: The path for the API endpoint.
        :param params: A dictionary of query parameters.
        :param version: (Legacy) The REST API version to use. If provided, implies a REST call.
        :param rest: If True, forces the call to use the REST API.
        :return: A requests.Response object.
        """
        # For backward compatibility, if version is passed, assume it's a REST call.
        if version:
            rest = True

        path = cleanup_path(path)
        if not params:
            params = {}

        if rest:
            base_url = self.rest_api_url
            # Only add version if it's not part of a paginated URL
            if "version" not in params and "version" not in path:
                params["version"] = version or self.version

            # Python Bools are True/False, JS Bools are true/false
            for k, v in params.items():
                if isinstance(v, bool):
                    params[k] = str(v).lower()

            # Don't pass params if the path is a fully-formed paginated URL
            if "snyk.io" in path:
                url = path
                fkwargs = {"headers": self.api_headers}
            else:
                url = f"{base_url}/{path}"
                fkwargs = {"headers": self.api_headers, "params": params}
        else:  # v1 API call
            url = f"{self.api_url}/{path}"
            fkwargs = {"headers": self.api_headers, "params": params}

        logger.debug(f"GET: {url} with params {params}")

        resp = retry_call(
            self.request,
            fargs=[requests.get, url],
            fkwargs=fkwargs,
            tries=self.tries,
            delay=self.delay,
            backoff=self.backoff,
            logger=logger,
        )
        if not resp.ok:
            logger.error(resp.text)
            raise SnykHTTPError(resp)

        return resp

    def delete(self, path: str, rest: bool = False) -> requests.Response:
        """
        Makes a DELETE request to the Snyk API.

        :param path: The path for the API endpoint.
        :param rest: If True, targets the REST API. Otherwise, targets the v1 API.
        :return: A requests.Response object.
        """
        if rest:
            base_url = self.rest_api_url
            params = {}
            if self.version:
                params["version"] = self.version
            fkwargs = {"headers": self.api_headers, "params": params}
        else:
            base_url = self.api_url
            fkwargs = {"headers": self.api_headers}

        url = f"{base_url}/{cleanup_path(path)}"
        logger.debug(f"DELETE: {url}")

        resp = retry_call(
            self.request,
            fargs=[requests.delete, url],
            fkwargs=fkwargs,
            tries=self.tries,
            delay=self.delay,
            backoff=self.backoff,
            logger=logger,
        )
        if not resp.ok:
            logger.error(resp.text)
            raise SnykHTTPError(resp)

        return resp

    def get_rest_pages(self, path: str, params: dict = {}) -> List:
        """
        Helper function to collect paginated responses from the rest API into a single
        list.

        This collects the "data" list from the first response and then appends the
        any further "data" lists if a next link is found in the links field.
        """
        first_page_response = self.get(path, params, rest=True)
        page_data = first_page_response.json()
        return_data = page_data["data"]

        while page_data.get("links", {}).get("next"):
            logger.debug(
                f"GET_REST_PAGES: Another link exists: {page_data['links']['next']}"
            )

            # Process links to get the next url
            if "next" in page_data["links"]:
                # If the next url is the same as the current url, break out of the loop
                if (
                    "self" in page_data["links"]
                    and page_data["links"]["next"] == page_data["links"]["self"]
                ):
                    break
                else:
                    next_url = page_data.get("links", {}).get("next")
            else:
                # If there is no next url, break out of the loop
                break

            # The next url comes back fully formed, so we pass it directly.
            next_page_response = self.get(next_url, rest=True)
            page_data = next_page_response.json()

            # Verify that response contains data
            if "data" in page_data:
                # If the data is empty, break out of the loop
                if len(page_data["data"]) == 0:
                    break
            # If response does not contain data, break out of the loop
            else:
                break

            # Append the data from the next page to the return data
            return_data.extend(page_data["data"])
            logger.debug(
                f"GET_REST_PAGES: Added another {len(page_data['data'])} items to the response"
            )
        return return_data

    # alias for backwards compatibility where V3 was the old name
    get_v3_pages = get_rest_pages

    @property
    def organizations(self) -> Manager:
        return Manager.factory(Organization, self)

    @property
    def projects(self) -> Manager:
        return Manager.factory(Project, self)

    @property
    def groups(self) -> Manager:
        return Manager.factory(Group, self)

    @property
    def users(self) -> Manager:
        return Manager.factory(RestUser, self)

    @property
    def me(self) -> "RestUser":
        """The current user."""
        resp = self.get("self", rest=True)
        return RestUser.from_dict(resp.json()["data"])

    @property
    def audit_logs(self) -> Manager:
        return Manager.factory("AuditLog", self)

    @property
    def integrations(self) -> Manager:
        return Manager.factory("Integration", self)

    # https://snyk.docs.apiary.io/#reference/reporting-api/issues/get-list-of-issues
    def issues(self):
        raise SnykNotImplementedError  # pragma: no cover
