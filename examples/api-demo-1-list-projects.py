import argparse

from pysnyk import SnykClient
from utils import get_token


def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument(
        "--orgId", type=str, help="The Snyk Organisation ID", required=True
    )

    return parser.parse_args()


snyk_token = get_token("snyk-api-token")
args = parse_command_line_args()
org_id = args.orgId

client = SnykClient(token=snyk_token)
for proj in client.organization(org_id).projects:
    print("\nProject name: %s" % proj.name)
    print("  Issues Found:")
    print("      High  : %s" % proj.issueCountsBySeverity.high)
    print("      Medium: %s" % proj.issueCountsBySeverity.medium)
    print("      Low   : %s" % proj.issueCountsBySeverity.low)
