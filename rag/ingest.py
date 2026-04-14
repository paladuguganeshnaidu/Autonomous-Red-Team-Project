import glob
import hashlib
import json
import os
from datetime import datetime

import config
from rag.chunker import chunk_text, normalize_text


class RAGIngestor:
    def __init__(self, embedder, vector_store, manifest_path):
        self.embedder = embedder
        self.vector_store = vector_store
        self.manifest_path = manifest_path
        self._known_hashes = self._load_known_hashes()

    def _load_known_hashes(self):
        hashes = set()
        for item in self.vector_store.records:
            metadata = item.get("metadata", {}) or {}
            chunk_hash = str(metadata.get("chunk_hash", "")).strip()
            if chunk_hash:
                hashes.add(chunk_hash)
        return hashes

    def _write_manifest(self, added_count, reason, target="", run_id=""):
        payload = {}
        if os.path.exists(self.manifest_path):
            try:
                with open(self.manifest_path, "r", encoding="utf-8") as file_handle:
                    payload = json.load(file_handle)
            except Exception:
                payload = {}

        payload["last_updated_at"] = datetime.now().isoformat()
        payload["last_reason"] = reason
        payload["last_target"] = target
        payload["last_run_id"] = run_id
        payload["total_records"] = self.vector_store.count
        payload["last_added_count"] = int(added_count or 0)

        os.makedirs(os.path.dirname(self.manifest_path), exist_ok=True)
        with open(self.manifest_path, "w", encoding="utf-8") as file_handle:
            json.dump(payload, file_handle, indent=2)

    def _iter_source_files(self):
        files = set()
        for pattern in config.RAG_SOURCE_GLOBS:
            for path in glob.glob(pattern, recursive=True):
                if os.path.isfile(path):
                    files.add(os.path.normpath(path))
        return sorted(files)

    @staticmethod
    def _read_file(path):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as file_handle:
                return file_handle.read()
        except Exception:
            return ""

    def _build_file_documents(self):
        docs = []
        for path in self._iter_source_files():
            text = self._read_file(path)
            text = normalize_text(text)
            if len(text) < 120:
                continue
            if len(text) > 120000:
                text = f"{text[:120000]} ..."

            docs.append(
                {
                    "text": text,
                    "metadata": {
                        "source_type": "workspace_file",
                        "source_path": os.path.relpath(path, config.BASE_DIR).replace("\\", "/"),
                    },
                }
            )
        return docs

    def _build_payload_documents(self):
        payload_sources = [
            ("xss", os.path.join(config.BASE_DIR, "wordlists", "Wordlists", "xss.txt")),
            ("lfi", os.path.join(config.BASE_DIR, "wordlists", "Wordlists", "lfi-payloads.txt")),
            ("ssti", os.path.join(config.BASE_DIR, "wordlists", "Wordlists", "ssti_wordlist.txt")),
            ("headers", os.path.join(config.BASE_DIR, "wordlists", "Wordlists", "headers_inject.txt")),
        ]

        docs = []
        for payload_type, path in payload_sources:
            if not os.path.exists(path):
                continue
            lines = []
            for line in self._read_file(path).splitlines():
                clean = line.strip()
                if not clean or clean.startswith("#"):
                    continue
                lines.append(clean)
                if len(lines) >= 600:
                    break
            if not lines:
                continue

            text = "\n".join(
                [
                    f"Payload category: {payload_type}",
                    "Candidate payload samples:",
                    *lines,
                ]
            )
            docs.append(
                {
                    "text": text,
                    "metadata": {
                        "source_type": "payload_knowledge",
                        "payload_type": payload_type,
                        "source_path": os.path.relpath(path, config.BASE_DIR).replace("\\", "/"),
                    },
                }
            )

        return docs

    def _prepare_chunks(self, documents, base_metadata=None):
        texts = []
        metadata_list = []
        base_metadata = base_metadata or {}

        for doc in documents:
            text = normalize_text(doc.get("text", ""))
            if not text:
                continue

            chunks = chunk_text(
                text,
                min_words=config.RAG_CHUNK_MIN_WORDS,
                max_words=config.RAG_CHUNK_MAX_WORDS,
                overlap_words=config.RAG_CHUNK_OVERLAP_WORDS,
            )
            if not chunks:
                continue

            source_metadata = {}
            source_metadata.update(base_metadata)
            source_metadata.update(doc.get("metadata", {}))

            for index, chunk in enumerate(chunks, start=1):
                payload = {
                    "chunk_index": index,
                    "word_count": len(chunk.split()),
                    "created_at": datetime.now().isoformat(),
                }
                payload.update(source_metadata)

                hash_input = f"{payload.get('source_type', '')}|{payload.get('source_path', '')}|{chunk}"
                chunk_hash = hashlib.sha1(hash_input.encode("utf-8")).hexdigest()
                payload["chunk_hash"] = chunk_hash

                if chunk_hash in self._known_hashes:
                    continue

                texts.append(chunk)
                metadata_list.append(payload)

        return texts, metadata_list

    def ingest_documents(self, documents, reason, target="", run_id=""):
        if not self.embedder.available:
            return 0

        texts, metadata_list = self._prepare_chunks(documents)
        if not texts:
            self._write_manifest(0, reason, target=target, run_id=run_id)
            return 0

        vectors = self.embedder.encode(texts)
        if vectors.shape[1] == 0:
            self._write_manifest(0, reason, target=target, run_id=run_id)
            return 0

        added = self.vector_store.add(vectors, texts, metadata_list)
        if added:
            self.vector_store.save()
            for item in metadata_list[:added]:
                self._known_hashes.add(item.get("chunk_hash", ""))

        self._write_manifest(added, reason, target=target, run_id=run_id)
        return added

    def bootstrap_from_workspace(self):
        docs = []
        docs.extend(self._build_file_documents())
        docs.extend(self._build_payload_documents())
        return self.ingest_documents(docs, reason="bootstrap")

    def ingest_iteration(self, target, run_id, iteration, scan_state, plan, command_results, analysis):
        command_summaries = []
        for item in command_results[:8]:
            summary = {
                "tool": item.get("tool"),
                "objective": item.get("objective"),
                "exit_code": item.get("exit_code"),
                "timed_out": item.get("timed_out"),
                "signals": item.get("verification", {}).get("signals", [])[:6],
                "analysis_input": (item.get("analysis_input") or "")[:3500],
            }
            command_summaries.append(summary)

        doc_text = json.dumps(
            {
                "target": target,
                "run_id": run_id,
                "iteration": iteration,
                "plan": {
                    "goal": plan.get("iteration_goal", ""),
                    "reasoning": plan.get("reasoning", ""),
                },
                "scan_state": {
                    "open_ports": scan_state.get("open_ports", []),
                    "services": scan_state.get("services", {}),
                    "urls": scan_state.get("urls", [])[:20],
                    "additional_hosts": scan_state.get("additional_hosts", [])[:20],
                },
                "analysis": analysis,
                "commands": command_summaries,
            },
            ensure_ascii=True,
            indent=2,
        )

        docs = [
            {
                "text": doc_text,
                "metadata": {
                    "source_type": "iteration_result",
                    "target": target,
                    "run_id": run_id,
                    "iteration": iteration,
                    "tool": "multi",
                },
            }
        ]
        return self.ingest_documents(docs, reason="iteration_update", target=target, run_id=run_id)

    def ingest_final(self, target, run_id, scan_state, final_assessment, iteration_records):
        compact_iterations = []
        for row in iteration_records[-8:]:
            compact_iterations.append(
                {
                    "iteration": row.get("iteration"),
                    "goal": row.get("iteration_goal"),
                    "summary": row.get("analysis_summary"),
                    "confidence": row.get("confidence", "medium"),
                    "vulns": row.get("vulnerability_candidates", [])[:10],
                }
            )

        doc_text = json.dumps(
            {
                "target": target,
                "run_id": run_id,
                "scan_state": scan_state,
                "final_assessment": final_assessment,
                "iteration_records": compact_iterations,
            },
            ensure_ascii=True,
            indent=2,
        )

        docs = [
            {
                "text": doc_text,
                "metadata": {
                    "source_type": "run_final_summary",
                    "target": target,
                    "run_id": run_id,
                    "iteration": len(iteration_records),
                    "tool": "final",
                },
            }
        ]
        return self.ingest_documents(docs, reason="final_update", target=target, run_id=run_id)
