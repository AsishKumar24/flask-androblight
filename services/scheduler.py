"""
Background Scheduler
=====================
APScheduler-based background job runner.

Schedules:
  - rescan_cached_hashes()  every 6 hours — re-checks VirusTotal for cached hashes
                             and marks changed verdicts in the database.
"""

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

_scheduler = None


def start_scheduler(app):
    """
    Start the background scheduler within the given Flask app context.
    Call this once from create_app() after all extensions are initialised.
    """
    global _scheduler

    if _scheduler is not None and _scheduler.running:
        return  # Already started

    from services.rescanner import rescan_cached_hashes

    _scheduler = BackgroundScheduler(daemon=True)

    # Re-check cached hashes every 6 hours
    _scheduler.add_job(
        func=lambda: _run_in_app_context(app, rescan_cached_hashes),
        trigger=IntervalTrigger(hours=6),
        id="rescan_cached_hashes",
        name="Periodic VirusTotal rescan",
        replace_existing=True,
        misfire_grace_time=300,  # Allow up to 5 min late execution
    )

    _scheduler.start()
    print("[Scheduler] Background scheduler started (rescan every 6 h)")


def _run_in_app_context(app, func):
    """Run a function inside a Flask application context."""
    with app.app_context():
        try:
            func()
        except Exception as exc:
            print(f"[Scheduler] Error in background job: {exc}")
