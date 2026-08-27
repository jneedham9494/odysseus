# shellcheck shell=bash
#
# Sourced, never executed -- so no shebang, and no `set -euo pipefail`, which would mutate the
# caller's shell. Same reasoning as ci-cost-classify.sh beside it.
#
# Decides whether THIS run of the review workflow delivered a verdict, from counts it is handed.
# It lives apart from the workflow so it can be exercised without GitHub, a token, or a pull
# request.
#
# That separation is not tidiness. The inline version regressed twice inside one pull request --
# counting every comment ever posted rather than this run's, and accepting a comment as a
# verdict after the prompt had stopped asking for one -- and both were found by hand, after the
# fact. A `>` for a `>=`, or `submitted_at` for `created_at`, shells out cleanly and shows
# itself only on a live run.

# review_gate_verdict REVIEWS COMMENTS
#
# Echoes what was delivered, or why nothing was, and returns non-zero when nothing was.
review_gate_verdict() {
  local reviews="${1:-}" comments="${2:-}"

  # A count that is not a number is not a zero. An empty string or an error message arriving
  # here and being treated as 0 is how a failed lookup reads as a genuine absence -- the defect
  # this repository exists to detect, and the reason ci-cost-classify.sh was extracted.
  if ! [[ "$reviews" =~ ^[0-9]+$ ]] || ! [[ "$comments" =~ ^[0-9]+$ ]]; then
    echo "the verdict count could not be read (reviews=${reviews:-<empty>}, comments=${comments:-<empty>}); treating as a failed review"
    return 1
  fi

  if [ "$reviews" -gt 0 ]; then
    echo "delivered: $reviews formal review(s)"
    return 0
  fi
  if [ "$comments" -gt 0 ]; then
    # Accepted, and named as the older shape. The allowlist no longer permits `gh pr comment`,
    # so a new run cannot produce this -- a re-run of an older pull request can.
    echo "delivered: $comments comment(s), the older shape"
    return 0
  fi
  echo "no verdict was delivered by this run"
  return 1
}

# review_gate_count JSON TIME_FIELD STARTED
#
# Counts the verdicts github-actions[bot] delivered strictly after STARTED, from a GitHub API
# response body. Echoes the count; echoes nothing and returns non-zero when the body will not
# parse -- which review_gate_verdict then refuses rather than reading as a genuine zero.
#
# This is the half that actually regressed, twice, inside one pull request: the time filter was
# absent, and the field name belonged to the other endpoint. Both shell out cleanly and show
# themselves only on a live run, so both are pinned by fixtures below in review-gate-test.sh.
#
# TIME_FIELD differs by endpoint and is passed rather than assumed: `/pulls/N/reviews` stamps
# `submitted_at`, `/issues/N/comments` stamps `created_at`. A response filtered on the other
# endpoint's field selects nothing and reads as "no verdict" -- a false failure, but a loud one.
#
# The comparison is lexicographic and correct only because both sides are RFC-3339 UTC in the
# same fixed width: `date -u +%Y-%m-%dT%H:%M:%SZ` produces exactly what GitHub returns.
#
# Accepts either a flat list of records or a list of pages, because `gh api --paginate --slurp`
# returns the second: one array per page, wrapped. Flattening here rather than at the call site
# is the same lesson as the wrappers below -- logic in the workflow is logic no fixture reaches,
# and this file exists because that is how the counting broke twice already.
#
# Pagination matters rather than being hypothetical: this pull request accumulated eight reviews
# while it was open, and an unpaginated call truncates in silence at a page boundary. It fails in
# the safer direction -- these endpoints return oldest-first, so a truncated fetch misses the
# run's own review and the gate goes red -- but "silently truncated" is the defect class, not an
# acceptable failure mode.
#
# A body that is valid JSON but not an array is refused rather than counted: `{}` -- which is
# what an error payload looks like -- otherwise reads as a genuine zero, the exact substitution
# this file was extracted to prevent.
#
# `>` and not `>=`: a verdict stamped in the same second as STARTED is not counted. STARTED is
# taken before the agent starts, so that costs a false failure at worst, never a false pass --
# and the whole point of the step is that it must not pass on someone else's review.
review_gate_count() {
  local json="${1:-}" field="${2:-}" started="${3:-}"

  # The boundary is refused if it is not a boundary.
  #
  # `review_gate_verdict` already refuses a count it cannot read rather than treating it as a
  # genuine zero. The timestamp had no such guard, and an empty one is worse than an unreadable
  # count: jq compares every candidate against "", "" sorts before every string, so
  # `.[$f] > ""` is true for **every bot verdict ever posted** and the gate silently reverts to
  # "any bot comment ever" -- the exact bug this file was written to fix.
  #
  # `${{ steps.started.outputs.at }}` renders as the empty string when the step id drifts.
  # GitHub Actions does not error on a missing output, so nothing else would say a word. This
  # file's own history records that drift happening once already: "a STARTED variable was
  # declared for exactly this and never wired in".
  #
  # Anchored to the shape the `started` step emits, `date -u +%Y-%m-%dT%H:%M:%SZ`. A looser
  # check would accept the values that break the comparison, which is the only reason to have
  # one. Found by the reviewer, round 13 of #106 (issue #150).
  if ! [[ "$started" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
    return 1
  fi
  # No `-e`: it guards against a null or false result, and this filter only ever yields a
  # number. The non-zero on a body that will not parse is jq's own, and dropping `-e` was
  # mutation-tested to confirm the fixture below is pinning that and not the flag.
  jq --arg f "$field" --arg t "$started" \
    'if type != "array" then error("not a list of verdicts") else
       (if (.[0] | type) == "array" then add else . end)
       | [.[] | select(.user.login == "github-actions[bot]") | select(.[$f] > $t)] | length end' \
    <<<"$json" 2>/dev/null
}

# review_gate_count_reviews JSON STARTED  /  review_gate_count_comments JSON STARTED
#
# The endpoint's time field is chosen here, not by the caller.
#
# `review_gate_count` takes the field as an argument, and the two call sites in the workflow
# pair reviews with `submitted_at` and comments with `created_at`. Transpose that pairing and
# every fixture below still passes -- the function behaves correctly for whatever field it is
# handed, so nothing in the unit tests is about the pairing. Live, `.[$f]` reads null on every
# element of both bodies (the Reviews API has no `created_at`, the Comments API has no
# `submitted_at`), both counts come back 0, and the gate reports "no verdict was delivered" on
# every future pull request: the `review` check red on every change, which is the failure the
# top of claude-review.yml already argues against for `preflight`.
#
# Units on both sides of a join and nothing on the join -- the same shape this repository has
# hit repeatedly. The fix is not another test at the call site; it is to leave no argument there
# to transpose. Found by the reviewer, twice, on the pull request that introduced it.
review_gate_count_reviews() { review_gate_count "${1:-}" submitted_at "${2:-}"; }
review_gate_count_comments() { review_gate_count "${1:-}" created_at "${2:-}"; }
