"""guardian_db — SQLAlchemy models, session management, and repositories.

Import `Base` and the models package to get the full metadata (used by Alembic and by
`Base.metadata.create_all` in the baseline migration).
"""

from guardian_db.base import Base
from guardian_db.session import get_session, session_scope

__all__ = ["Base", "get_session", "session_scope"]
