import sqlite3
from langgraph.checkpoint.sqlite import SqliteSaver

# Persistent SQLite database file for state checkpoints
DB_PATH = "checkpoints.sqlite"

_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
_checkpointer_instance = SqliteSaver(_conn)

def get_checkpointer() -> SqliteSaver:
    """Returns the persistent SQLite LangGraph checkpointer instance."""
    return _checkpointer_instance
