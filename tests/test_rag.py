from src.agents.security_agent import attach_standards
from src.rag.embeddings import HashingEmbedding
from src.rag.vector_store import initialize_vector_store, load_standard_nodes, retrieve_standards

LABELLED_QUERIES = {
    "SQL injection via dynamic query construction": "SEC-09",
    "Insecure deserialization pickle.loads": "SEC-25",
    "Server-side request forgery URL derived from user input": "SEC-29",
    "Route handler without authorization": "SEC-01",
    "Weak hash algorithm MD5": "SEC-05",
    "N+1 database query inside loop": "STD-07",
    "bare except clause": "STD-04",
    "Hard-coded credential API key": "SEC-21",
    "Debug mode enabled": "SEC-16",
    "Sensitive data written to logs password": "SEC-27",
    "JWT signature verification disabled": "SEC-22",
    "mutable default argument": "STD-05",
    "OS command injection os.system": "SEC-10",
    "Permissive CORS policy": "SEC-17",
    "Path traversal file path user input": "SEC-03",
    "TLS certificate verification disabled": "SEC-23",
    "Exception silently swallowed": "SEC-28",
    "XML parsing XXE": "SEC-18",
    "Code injection via eval/exec": "SEC-11",
    "Cross-site scripting unescaped HTML": "SEC-12",
    "Plaintext password comparison": "SEC-24",
    "unit test for function raising ValueError": "TST-02",
}


def test_standards_are_chunked_per_rule():
    nodes = load_standard_nodes()
    ids = {n.metadata["rule_id"] for n in nodes}
    assert len(nodes) >= 45
    assert {"SEC-01", "SEC-29", "STD-07", "TST-02", "DOC-01"} <= ids


def test_index_uses_vector_embeddings():
    index = initialize_vector_store(force=True)
    assert isinstance(index._embed_model, HashingEmbedding)
    vec = index._embed_model.get_text_embedding("parameterised SQL queries")
    assert len(vec) == index._embed_model.dim
    assert abs(sum(v * v for v in vec) - 1.0) < 1e-6


def test_retrieval_top3_hit_rate():
    hits = sum(expected in [h["rule_id"] for h in retrieve_standards(q, 3)] for q, expected in LABELLED_QUERIES.items())
    assert hits / len(LABELLED_QUERIES) >= 0.9


def test_retrieval_results_are_ranked_by_similarity():
    results = retrieve_standards("SQL injection parameterised queries", 3)
    scores = [r["score"] for r in results]
    assert scores == sorted(scores, reverse=True)


def test_findings_are_grounded_with_standard_citations():
    finding = attach_standards({"title": "SQL injection via dynamic query construction",
                                "description": "SQL built with f-string"})
    assert finding["standard_refs"][0]["rule_id"] == "SEC-09"
