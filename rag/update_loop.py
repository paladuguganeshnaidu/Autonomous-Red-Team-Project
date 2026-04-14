import os

import config
from rag.embedder import TextEmbedder
from rag.ingest import RAGIngestor
from rag.query_builder import build_retrieval_query
from rag.retriever import RAGRetriever
from rag.vector_store import FaissVectorStore


class RAGUpdateLoop:
    def __init__(self, trace_logger=None):
        self.trace_logger = trace_logger
        self.enabled = bool(config.RAG_ENABLED)
        self.last_error = ""

        self.embedder = None
        self.vector_store = None
        self.retriever = None
        self.ingestor = None

        if not self.enabled:
            return

        os.makedirs(config.RAG_INDEX_DIR, exist_ok=True)
        os.makedirs(config.RAG_DATA_DIR, exist_ok=True)

        self.embedder = TextEmbedder(config.RAG_EMBED_MODEL, batch_size=config.RAG_EMBED_BATCH_SIZE)
        self.vector_store = FaissVectorStore(config.RAG_FAISS_INDEX_PATH, config.RAG_METADATA_PATH)
        self.vector_store.load()
        self.retriever = RAGRetriever(embedder=self.embedder, vector_store=self.vector_store)
        self.ingestor = RAGIngestor(
            embedder=self.embedder,
            vector_store=self.vector_store,
            manifest_path=config.RAG_INGEST_MANIFEST_PATH,
        )

        if not self.embedder.available:
            self.last_error = self.embedder.error or "RAG embedder unavailable"
            self._log_event("rag_init", status="degraded", error=self.last_error)
        else:
            self._log_event("rag_init", status="ready", records=self.vector_store.count)

    def _log_event(self, event_type, **kwargs):
        if self.trace_logger:
            self.trace_logger.log_event(event_type, **kwargs)

    def bootstrap(self):
        if not self.enabled or not config.RAG_BOOTSTRAP_ON_START or not self.ingestor:
            return 0
        try:
            added = self.ingestor.bootstrap_from_workspace()
            self._log_event("rag_bootstrap", added=added, total_records=self.vector_store.count)
            return added
        except Exception as exc:
            self.last_error = str(exc)
            self._log_event("rag_bootstrap", added=0, error=self.last_error)
            return 0

    def retrieve_for_stage(self, scan_state, stage, plan=None, analysis=None, command_results=None):
        if not self.enabled or not self.retriever:
            return {"query": "", "results": [], "context": ""}

        try:
            query = build_retrieval_query(
                scan_state=scan_state,
                stage=stage,
                plan=plan,
                analysis=analysis,
                command_results=command_results,
            )
            results = self.retriever.retrieve(
                query,
                top_k=config.RAG_TOP_K,
                min_similarity=config.RAG_MIN_SIMILARITY,
            )
            context = self.retriever.format_context(results, max_chars=config.RAG_MAX_CONTEXT_CHARS)
            self._log_event(
                "rag_retrieval",
                stage=stage,
                query=query,
                result_count=len(results),
                top_scores=[round(float(item.get("score", 0.0)), 4) for item in results[:5]],
            )
            return {"query": query, "results": results, "context": context}
        except Exception as exc:
            self.last_error = str(exc)
            self._log_event("rag_retrieval", stage=stage, query="", result_count=0, error=self.last_error)
            return {"query": "", "results": [], "context": ""}

    def ingest_iteration(self, target, run_id, iteration, scan_state, plan, command_results, analysis):
        if not self.enabled or not config.RAG_UPDATE_AFTER_ITERATION or not self.ingestor:
            return 0
        try:
            added = self.ingestor.ingest_iteration(
                target=target,
                run_id=run_id,
                iteration=iteration,
                scan_state=scan_state,
                plan=plan,
                command_results=command_results,
                analysis=analysis,
            )
            self._log_event(
                "rag_iteration_update",
                target=target,
                run_id=run_id,
                iteration=iteration,
                added=added,
                total_records=self.vector_store.count,
            )
            return added
        except Exception as exc:
            self.last_error = str(exc)
            self._log_event(
                "rag_iteration_update",
                target=target,
                run_id=run_id,
                iteration=iteration,
                added=0,
                error=self.last_error,
            )
            return 0

    def ingest_final(self, target, run_id, scan_state, final_assessment, iteration_records):
        if not self.enabled or not config.RAG_UPDATE_AFTER_RUN or not self.ingestor:
            return 0
        try:
            added = self.ingestor.ingest_final(
                target=target,
                run_id=run_id,
                scan_state=scan_state,
                final_assessment=final_assessment,
                iteration_records=iteration_records,
            )
            self._log_event(
                "rag_final_update",
                target=target,
                run_id=run_id,
                added=added,
                total_records=self.vector_store.count,
            )
            return added
        except Exception as exc:
            self.last_error = str(exc)
            self._log_event("rag_final_update", target=target, run_id=run_id, added=0, error=self.last_error)
            return 0
