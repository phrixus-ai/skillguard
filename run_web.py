#!/usr/bin/env python3
"""Run SkillGuard Web UI."""

from skillguard.web.app import create_app

app = create_app()
app.run(host="0.0.0.0", port=5000, debug=False)
