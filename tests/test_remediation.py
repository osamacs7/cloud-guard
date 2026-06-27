from cloud_guard.remediation.playbooks import get_playbook, get_remediation_commands


class TestPlaybooks:
    def test_known_playbook(self):
        playbook = get_playbook("CG-AWS-S3-001")
        assert playbook is not None
        assert playbook.auto_remediable is True
        assert len(playbook.steps) == 2

    def test_unknown_playbook(self):
        assert get_playbook("NONEXISTENT") is None

    def test_remediation_commands(self):
        commands = get_remediation_commands("CG-AWS-S3-001", "my-bucket")
        assert len(commands) == 2
        assert "my-bucket" in commands[0]["command"]

    def test_k8s_playbook(self):
        playbook = get_playbook("CG-K8S-POD-001")
        assert playbook is not None
        assert playbook.provider == "k8s"
        assert playbook.auto_remediable is False
