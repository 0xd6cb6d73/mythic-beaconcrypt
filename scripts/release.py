#!/usr/bin/env python3
"""Prepare and finalize an image release without publishing an unbuilt config."""

import argparse
import base64
import copy
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass


ZERO = "0" * 40
FOOTER = "Co-authored-by: Codex <codex@openai.com>"
AUTO_VERSION = re.compile(r"v0\.1\.([1-9][0-9]*)\Z")


class ReleaseError(RuntimeError):
    pass


class APIError(ReleaseError):
    pass


@dataclass(frozen=True)
class Release:
    repository: str
    source: str
    version: str
    run_id: str

    def __post_init__(self):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", self.repository):
            raise ReleaseError("Invalid GITHUB_REPOSITORY")
        if not re.fullmatch(r"[0-9a-f]{40}", self.source):
            raise ReleaseError("Invalid GITHUB_SHA")
        if not AUTO_VERSION.fullmatch(self.version):
            raise ReleaseError("RELEASE_VERSION must have the form v0.1.<positive run number>")
        if not re.fullmatch(r"[0-9]+", self.run_id):
            raise ReleaseError("Invalid GITHUB_RUN_ID")

    @property
    def branch(self):
        return f"ci-release/{self.run_id}"

    @property
    def image(self):
        return f"ghcr.io/{self.repository.lower()}:{self.version}"


class GitHub:
    def __init__(self, repository, token):
        self.repository = repository
        self.token = token
        self.repository_id = None

    def request(self, path, method="GET", body=None, missing_ok=False):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            "https://api.github.com" + path,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "mythic-beaconcrypt-release",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if missing_ok and error.code == 404:
                return None
            try:
                message = json.load(error).get("message", error.reason)
            except (ValueError, AttributeError):
                message = error.reason
            raise APIError(f"GitHub {method} {path}: {error.code}: {message}") from error
        except urllib.error.URLError as error:
            raise APIError(f"GitHub request failed: {error.reason}") from error

    def graphql(self, query, variables):
        response = self.request("/graphql", "POST", {"query": query, "variables": variables})
        if response.get("errors"):
            raise APIError("; ".join(error["message"] for error in response["errors"]))
        return response["data"]

    def ref(self, name):
        path = urllib.parse.quote(name, safe="/")
        result = self.request(f"/repos/{self.repository}/git/ref/{path}", missing_ok=True)
        if result is None:
            return None
        target = result["object"]
        # Annotated tags are accepted, but their commits are never moved or replaced.
        for _ in range(10):
            if target["type"] == "commit":
                return target["sha"]
            if target["type"] != "tag":
                break
            target = self.request(f"/repos/{self.repository}/git/tags/{target['sha']}")["object"]
        raise ReleaseError(f"Ref {name} does not resolve to a commit")

    def create_branch(self, name, commit):
        self.request(
            f"/repos/{self.repository}/git/refs", "POST",
            {"ref": f"refs/heads/{name}", "sha": commit},
        )

    def config(self, commit):
        result = self.request(f"/repos/{self.repository}/contents/config.json?ref={commit}")
        if result.get("type") != "file" or result.get("encoding") != "base64":
            raise ReleaseError("config.json must be an ordinary JSON file")
        try:
            config = json.loads(base64.b64decode(result["content"]))
        except (ValueError, TypeError) as error:
            raise ReleaseError("config.json is not valid JSON") from error
        if not isinstance(config, dict):
            raise ReleaseError("config.json must contain an object")
        return config

    def commit(self, commit):
        # REST supplies changed paths; GraphQL identifies GitHub's own signature.
        result = self.request(f"/repos/{self.repository}/commits/{commit}")
        signature = self.graphql(
            """query($owner:String!, $name:String!, $oid:GitObjectID!) {
              repository(owner:$owner, name:$name) {
                object(oid:$oid) { ... on Commit {
                  signature { isValid wasSignedByGitHub }
                } }
              }
            }""",
            dict(zip(("owner", "name"), self.repository.split("/"))) | {"oid": commit},
        )["repository"]["object"]["signature"]
        return {
            "parents": [parent["sha"] for parent in result["parents"]],
            "message": result["commit"]["message"],
            "files": [file["filename"] for file in result["files"]],
            "signature": signature,
            "verified": result["commit"]["verification"]["verified"],
        }

    def signed_commit(self, branch, expected, config, headline, body):
        contents = base64.b64encode((json.dumps(config, indent=2) + "\n").encode()).decode()
        result = self.graphql(
            """mutation($input:CreateCommitOnBranchInput!) {
              createCommitOnBranch(input:$input) { commit { oid } }
            }""",
            {"input": {
                "branch": {"repositoryNameWithOwner": self.repository, "branchName": branch},
                "expectedHeadOid": expected,
                "message": {"headline": headline, "body": body},
                "fileChanges": {"additions": [{"path": "config.json", "contents": contents}]},
            }},
        )
        return result["createCommitOnBranch"]["commit"]["oid"]

    def update_refs(self, updates):
        if self.repository_id is None:
            self.repository_id = self.request(f"/repos/{self.repository}")["node_id"]
        self.graphql(
            """mutation($input:UpdateRefsInput!) {
              updateRefs(input:$input) { clientMutationId }
            }""",
            {"input": {"repositoryId": self.repository_id, "refUpdates": updates}},
        )

    def is_ancestor(self, ancestor, descendant):
        result = self.request(f"/repos/{self.repository}/compare/{ancestor}...{descendant}")
        return result["status"] in ("ahead", "identical")


def image_config(config, release):
    config = copy.deepcopy(config)
    images = config.setdefault("remote_images", {})
    if not isinstance(images, dict):
        raise ReleaseError("config.json remote_images must contain an object")
    images["mythic_beaconcrypt"] = release.image
    return config


def require_signature(commit):
    signature = commit.get("signature")
    if (
        not commit.get("verified") or not signature
        or not signature.get("isValid") or not signature.get("wasSignedByGitHub")
    ):
        raise ReleaseError("Release metadata commit must have a valid GitHub signature")


def validate_candidate(api, release, commit):
    metadata = api.commit(commit)
    require_signature(metadata)
    if metadata["parents"] != [release.source]:
        raise ReleaseError("Release candidate belongs to a different source commit")
    if metadata["files"] != ["config.json"]:
        raise ReleaseError("Release candidate must change only config.json")
    trailers = metadata["message"].splitlines()
    if f"Release-Source: {release.source}" not in trailers or FOOTER not in trailers:
        raise ReleaseError("Release candidate is missing its source or Codex footer")
    if api.config(commit) != image_config(api.config(release.source), release):
        raise ReleaseError("Release candidate config does not match its source and version")


def prepare(api, release):
    tag = api.ref(f"tags/{release.version}")
    if tag is not None:
        validate_candidate(api, release, tag)
        return tag, True
    candidate = api.ref(f"heads/{release.branch}")
    if candidate is None:
        api.create_branch(release.branch, release.source)
        candidate = release.source
    if candidate == release.source:
        candidate = api.signed_commit(
            release.branch, release.source, image_config(api.config(release.source), release),
            f"Release {release.version}",
            f"Use the signed container image for this release.\n\nRelease-Source: {release.source}\n\n{FOOTER}",
        )
    validate_candidate(api, release, candidate)
    return candidate, False


def ref_update(name, before, after):
    return {"name": f"refs/{name}", "beforeOid": before or ZERO, "afterOid": after or ZERO}


def promote_config(api, release):
    """Preserve a moving main tree and never replace a newer release pointer."""
    for _ in range(5):
        head = api.ref("heads/main")
        if head is None or not api.is_ancestor(release.source, head):
            return
        config = api.config(head)
        desired = image_config(config, release)
        if config == desired:
            return
        current = config.get("remote_images", {}).get("mythic_beaconcrypt", "")
        prefix = f"ghcr.io/{release.repository.lower()}:"
        previous = None
        if isinstance(current, str) and current.startswith(prefix):
            previous = AUTO_VERSION.fullmatch(current.removeprefix(prefix))
        if previous and int(previous[1]) > int(AUTO_VERSION.fullmatch(release.version)[1]):
            return
        try:
            commit = api.signed_commit(
                "main", head, desired, f"Use container image {release.version}",
                f"Keep main's installer on a published, verified image.\n\nRelease-Source: {release.source}\n\n{FOOTER}",
            )
        except APIError:
            if api.ref("heads/main") != head:
                continue
            raise
        require_signature(api.commit(commit))
        return
    raise ReleaseError("main kept moving while updating its image reference; rerun the release")


def finalize(api, release, candidate):
    validate_candidate(api, release, candidate)
    for _ in range(5):
        tag = api.ref(f"tags/{release.version}")
        if tag is not None and tag != candidate:
            raise ReleaseError("Release tag already exists at a different commit; refusing to overwrite it")
        temporary = api.ref(f"heads/{release.branch}")
        if temporary is not None and temporary != candidate:
            raise ReleaseError("Temporary release branch moved; refusing to delete it")
        head = api.ref("heads/main")
        updates = []
        if tag is None:
            updates.append(ref_update(f"tags/{release.version}", None, candidate))
        if head == release.source:
            updates.append(ref_update("heads/main", head, candidate))
        if temporary is not None:
            updates.append(ref_update(f"heads/{release.branch}", temporary, None))
        if updates:
            try:
                api.update_refs(updates)
            except APIError:
                # Retry only if refs changed; authentication or policy errors must fail.
                latest = (
                    api.ref("heads/main"), api.ref(f"tags/{release.version}"),
                    api.ref(f"heads/{release.branch}"),
                )
                if latest != (head, tag, temporary):
                    continue
                raise
        promote_config(api, release)
        return
    raise ReleaseError("Release refs kept moving; rerun the release")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "finalize"))
    args = parser.parse_args()
    try:
        release = Release(*(os.environ[name] for name in (
            "GITHUB_REPOSITORY", "GITHUB_SHA", "RELEASE_VERSION", "GITHUB_RUN_ID",
        )))
        api = GitHub(release.repository, os.environ["GH_TOKEN"])
        if args.command == "prepare":
            candidate, released = prepare(api, release)
            output = f"commit={candidate}\nreleased={str(released).lower()}\n"
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
                stream.write(output)
            print(output, end="")
        else:
            finalize(api, release, os.environ["RELEASE_COMMIT"])
            print(f"Finalized {release.version}: {release.image}")
    except (KeyError, ReleaseError, ValueError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
