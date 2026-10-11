import sys

from tsunamiwall.cli import main


def test_main_accepts_config_before_command(monkeypatch, tmp_path):
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("max_honeypots: 5\n", encoding="utf-8")

    # We only care that argument parsing succeeds; the daemon path is not run.
    argv = ["-c", str(cfg), "start", "--help"]
    monkeypatch.setattr(sys, "argv", ["tsunamiwall"] + argv)
    # argparse calls sys.exit on --help; catch it as success.
    with monkeypatch.context():
        try:
            main(argv)
        except SystemExit as exc:
            assert exc.code == 0


def test_main_accepts_config_after_command(monkeypatch, tmp_path):
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("max_honeypots: 5\n", encoding="utf-8")

    argv = ["start", "-c", str(cfg), "--help"]
    monkeypatch.setattr(sys, "argv", ["tsunamiwall"] + argv)
    try:
        main(argv)
    except SystemExit as exc:
        assert exc.code == 0
