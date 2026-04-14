import config
from rag.embedder import TextEmbedder
from rag.vector_store import FaissVectorStore


class RAGRetriever:
    def __init__(self, embedder=None, vector_store=None):
        self.embedder = embedder or TextEmbedder(config.RAG_EMBED_MODEL, batch_size=config.RAG_EMBED_BATCH_SIZE)
        self.vector_store = vector_store or FaissVectorStore(
            config.RAG_FAISS_INDEX_PATH,
            config.RAG_METADATA_PATH,
        )
        self.last_error = ""

        if vector_store is None:
            self.vector_store.load()

    @property
    def ready(self):
        return (
            self.embedder.available
            and self.vector_store.available
            and self.vector_store.count > 0
        )

    def retrieve(self, query, top_k=None, min_similarity=None):
        query_text = str(query or "").strip()
        if not query_text:
            return []
        if not self.embedder.available:
            self.last_error = self.embedder.error or "embedder unavailable"
            return []
        if not self.vector_store.available:
            self.last_error = "vector store unavailable"
            return []
        if self.vector_store.count == 0:
            return []

        effective_top_k = int(top_k or config.RAG_TOP_K)
        effective_top_k = max(3, min(5, effective_top_k))
        similarity_threshold = float(min_similarity if min_similarity is not None else config.RAG_MIN_SIMILARITY)

        query_vectors = self.embedder.encode([query_text])
        if query_vectors.shape[1] == 0:
            self.last_error = "query embedding failed"
            return []

        raw_results = self.vector_store.search(query_vectors[0], top_k=effective_top_k)
        filtered = [item for item in raw_results if float(item.get("score", 0.0)) >= similarity_threshold]

        return filtered[:effective_top_k]

    @staticmethod
    def format_context(results, max_chars=None):
        if not results:
            return ""

        hard_limit = int(max_chars or config.RAG_MAX_CONTEXT_CHARS)
        lines = []

        for index, item in enumerate(results, start=1):
            metadata = item.get("metadata", {}) or {}
            lines.append(
                " ".join(
                    [
                        f"[CONTEXT {index}]",
                        f"score={float(item.get('score', 0.0)):.3f}",
                        f"source={metadata.get('source_type', 'unknown')}",
                        f"target={metadata.get('target', '')}",
                        f"tool={metadata.get('tool', '')}",
                        f"iteration={metadata.get('iteration', '')}",
                    ]
                ).strip()
            )
            snippet = str(item.get("text", "")).strip()
            if len(snippet) > 900:
                snippet = f"{snippet[:900]} ..."
            lines.append(snippet)
            lines.append("")

            if len("\n".join(lines)) >= hard_limit:
                break

        context = "\n".join(lines).strip()
        if len(context) > hard_limit:
            context = f"{context[:hard_limit]} ..."
        return context
