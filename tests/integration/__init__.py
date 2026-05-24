# tests/integration/ -- Phase C4
#
# Tests in this directory spin up the full docker compose stack and
# exercise it end-to-end. unittest discover IS recursive, so these
# files show up alongside the unit suite -- but every test class is
# decorated with @unittest.skipUnless(AIB_RUN_INTEGRATION == "1", ...)
# so they skip in <1ms when the env var is unset.
#
# Run manually:
#   AIB_RUN_INTEGRATION=1 python -m unittest discover -s tests/integration -v
#
# Run in CI:
#   The "integration" job in .github/workflows/integration.yml is
#   workflow_dispatch + weekly cron (not on every PR) because the
#   compose stack takes 3-5 minutes to come up.
