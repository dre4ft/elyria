"""Shared auth helpers — re-exports from core.auth for backwards compatibility."""

# All new code should import from core.auth directly.
# These re-exports keep existing imports working.
from core.auth import get_user as get_auth_user
from core.auth import get_user_teams as get_auth_user_teams
from core.auth import require_admin
from core.auth import verify_team_membership
from core.auth import verify_ownership
from core.auth import get_followed_team_ids
