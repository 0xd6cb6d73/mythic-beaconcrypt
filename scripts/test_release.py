"""Release safety tests; no GitHub token or network is needed."""

import copy
import importlib.util
from pathlib import Path
import sys
import unittest


spec = importlib.util.spec_from_file_location("release", Path(__file__).with_name("release.py"))
release = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = release
spec.loader.exec_module(release)

SOURCE = "1" * 40
NEWER = "2" * 40
SETTINGS = release.Release("Owner/Provider", SOURCE, "v0.1.42", "9001")
CONFIG = {
    "exclude_payload_type": False,
    "provider_option": {"keep": True},
    "remote_images": {"another_service": "example/other:v3"},
}


class FakeAPI:
    def __init__(self):
        self.refs = {"heads/main": SOURCE}
        self.configs = {SOURCE: copy.deepcopy(CONFIG)}
        self.commits = {}
        self.parents = {SOURCE: []}
        self.next_commit = 100
        self.ref_updates = []
        self.signed_commits = []
        self.before_update = None
        self.before_signed = None

    def ref(self, name):
        return self.refs.get(name)

    def create_branch(self, name, commit):
        if f"heads/{name}" in self.refs:
            raise release.APIError("branch exists")
        self.refs[f"heads/{name}"] = commit

    def config(self, commit):
        return copy.deepcopy(self.configs[commit])

    def commit(self, commit):
        return copy.deepcopy(self.commits[commit])

    def signed_commit(self, branch, expected, config, headline, body):
        if self.before_signed:
            callback, self.before_signed = self.before_signed, None
            callback(self)
        if self.ref(f"heads/{branch}") != expected:
            raise release.APIError("stale branch head")
        commit = f"{self.next_commit:040x}"
        self.next_commit += 1
        self.configs[commit] = copy.deepcopy(config)
        self.parents[commit] = [expected]
        self.commits[commit] = {
            "parents": [expected],
            "message": headline + "\n\n" + body,
            "files": ["config.json"],
            "verified": True,
            "signature": {"isValid": True, "wasSignedByGitHub": True},
        }
        self.refs[f"heads/{branch}"] = commit
        self.signed_commits.append((branch, commit))
        return commit

    def update_refs(self, updates):
        if self.before_update:
            callback, self.before_update = self.before_update, None
            callback(self)
        for update in updates:
            name = update["name"].removeprefix("refs/")
            if (self.ref(name) or release.ZERO) != update["beforeOid"]:
                raise release.APIError("stale ref")
            if update.get("force"):
                raise AssertionError("Releases must never force refs")
        self.ref_updates.append(copy.deepcopy(updates))
        for update in updates:
            name = update["name"].removeprefix("refs/")
            if update["afterOid"] == release.ZERO:
                self.refs.pop(name, None)
            else:
                self.refs[name] = update["afterOid"]

    def is_ancestor(self, ancestor, descendant):
        return ancestor == descendant or any(
            self.is_ancestor(ancestor, parent) for parent in self.parents.get(descendant, [])
        )

    def advance_main(self, config=None, parent=SOURCE):
        self.refs["heads/main"] = NEWER
        self.configs[NEWER] = copy.deepcopy(config or CONFIG)
        self.parents[NEWER] = [parent]


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeAPI()

    def prepare(self):
        candidate, released = release.prepare(self.api, SETTINGS)
        self.assertFalse(released)
        return candidate

    def test_prepare_preserves_config_and_main(self):
        candidate = self.prepare()
        self.assertEqual(self.api.ref("heads/main"), SOURCE)
        self.assertIsNone(self.api.ref("tags/v0.1.42"))
        expected = copy.deepcopy(CONFIG)
        expected["remote_images"]["mythic_beaconcrypt"] = "ghcr.io/owner/provider:v0.1.42"
        self.assertEqual(self.api.config(candidate), expected)
        self.assertEqual(self.api.config(SOURCE), CONFIG)
        self.assertIn(release.FOOTER, self.api.commit(candidate)["message"])

    def test_prepare_retry_reuses_candidate(self):
        candidate = self.prepare()
        self.assertEqual(release.prepare(self.api, SETTINGS), (candidate, False))
        self.assertEqual(len(self.api.signed_commits), 1)

    def test_completed_retry_reuses_tag_without_new_commit(self):
        candidate = self.prepare()
        release.finalize(self.api, SETTINGS, candidate)
        self.assertEqual(release.prepare(self.api, SETTINGS), (candidate, True))
        release.finalize(self.api, SETTINGS, candidate)
        self.assertEqual(len(self.api.signed_commits), 1)

    def test_rejects_missing_invalid_and_non_github_signatures(self):
        for patch in (
            {"signature": None},
            {"verified": False},
            {"signature": {"isValid": False, "wasSignedByGitHub": True}},
            {"signature": {"isValid": True, "wasSignedByGitHub": False}},
        ):
            with self.subTest(patch=patch):
                self.api = FakeAPI()
                candidate = self.prepare()
                self.api.commits[candidate].update(patch)
                with self.assertRaisesRegex(release.ReleaseError, "valid GitHub signature"):
                    release.prepare(self.api, SETTINGS)
                self.assertIsNone(self.api.ref("tags/v0.1.42"))

    def test_tag_collision_at_different_source_is_rejected(self):
        candidate = self.prepare()
        self.api.refs["tags/v0.1.42"] = candidate
        self.api.commits[candidate]["parents"] = [NEWER]
        with self.assertRaisesRegex(release.ReleaseError, "different source"):
            release.prepare(self.api, SETTINGS)

    def test_candidate_extra_file_or_changed_other_config_is_rejected(self):
        candidate = self.prepare()
        self.api.commits[candidate]["files"].append("main.go")
        with self.assertRaisesRegex(release.ReleaseError, "only config.json"):
            release.prepare(self.api, SETTINGS)
        self.api.commits[candidate]["files"] = ["config.json"]
        self.api.configs[candidate]["provider_option"]["keep"] = False
        with self.assertRaisesRegex(release.ReleaseError, "does not match"):
            release.prepare(self.api, SETTINGS)

    def test_finalize_publishes_tag_main_and_cleanup_atomically(self):
        candidate = self.prepare()
        release.finalize(self.api, SETTINGS, candidate)
        self.assertEqual(self.api.ref("heads/main"), candidate)
        self.assertEqual(self.api.ref("tags/v0.1.42"), candidate)
        self.assertIsNone(self.api.ref(f"heads/{SETTINGS.branch}"))
        self.assertEqual(len(self.api.ref_updates), 1)
        self.assertEqual(len(self.api.ref_updates[0]), 3)

    def test_finalize_never_overwrites_existing_tag(self):
        candidate = self.prepare()
        self.api.refs["tags/v0.1.42"] = NEWER
        with self.assertRaisesRegex(release.ReleaseError, "refusing to overwrite"):
            release.finalize(self.api, SETTINGS, candidate)
        self.assertEqual(self.api.ref("tags/v0.1.42"), NEWER)
        self.assertEqual(self.api.ref("heads/main"), SOURCE)

    def test_advanced_main_preserves_new_config_fields_and_code_parent(self):
        candidate = self.prepare()
        advanced = copy.deepcopy(CONFIG)
        advanced["new_option"] = "new code"
        self.api.advance_main(advanced)
        release.finalize(self.api, SETTINGS, candidate)
        head = self.api.ref("heads/main")
        self.assertEqual(self.api.parents[head], [NEWER])
        self.assertEqual(self.api.config(head)["new_option"], "new code")
        self.assertEqual(self.api.config(head)["remote_images"]["another_service"], "example/other:v3")
        self.assertEqual(self.api.ref("tags/v0.1.42"), candidate)

    def test_older_run_never_rolls_back_newer_main_image(self):
        candidate = self.prepare()
        advanced = release.image_config(CONFIG, release.Release(SETTINGS.repository, SOURCE, "v0.1.43", "9002"))
        self.api.advance_main(advanced)
        release.finalize(self.api, SETTINGS, candidate)
        self.assertEqual(self.api.ref("heads/main"), NEWER)
        self.assertTrue(self.api.config(NEWER)["remote_images"]["mythic_beaconcrypt"].endswith(":v0.1.43"))
        self.assertEqual(self.api.ref("tags/v0.1.42"), candidate)

    def test_force_pushed_main_is_not_promoted(self):
        candidate = self.prepare()
        self.api.advance_main(parent="3" * 40)
        release.finalize(self.api, SETTINGS, candidate)
        self.assertEqual(self.api.ref("heads/main"), NEWER)
        self.assertEqual(self.api.config(NEWER), CONFIG)

    def test_atomic_ref_race_retries_without_losing_new_main(self):
        candidate = self.prepare()
        self.api.before_update = lambda api: api.advance_main()
        release.finalize(self.api, SETTINGS, candidate)
        self.assertEqual(self.api.parents[self.api.ref("heads/main")], [NEWER])
        self.assertEqual(self.api.ref("tags/v0.1.42"), candidate)
        self.assertEqual(len(self.api.ref_updates), 1)
        self.assertEqual(len(self.api.ref_updates[0]), 2)

    def test_config_commit_cas_race_preserves_latest_tree(self):
        candidate = self.prepare()
        self.api.advance_main()

        def move_again(api):
            newest = "3" * 40
            api.refs["heads/main"] = newest
            api.configs[newest] = copy.deepcopy(CONFIG) | {"newest_option": True}
            api.parents[newest] = [NEWER]

        self.api.before_signed = move_again
        release.finalize(self.api, SETTINGS, candidate)
        head = self.api.ref("heads/main")
        self.assertEqual(self.api.parents[head], ["3" * 40])
        self.assertTrue(self.api.config(head)["newest_option"])

    def test_policy_failure_without_ref_change_is_not_retried(self):
        candidate = self.prepare()

        def denied(_):
            raise release.APIError("branch protection denied update")

        self.api.before_update = denied
        with self.assertRaisesRegex(release.APIError, "branch protection"):
            release.finalize(self.api, SETTINGS, candidate)
        self.assertIsNone(self.api.ref("tags/v0.1.42"))
        self.assertEqual(self.api.ref("heads/main"), SOURCE)

    def test_other_remote_images_shape_is_rejected(self):
        self.api.configs[SOURCE]["remote_images"] = []
        with self.assertRaisesRegex(release.ReleaseError, "must contain an object"):
            release.prepare(self.api, SETTINGS)


if __name__ == "__main__":
    unittest.main()
