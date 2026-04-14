import json
import os

import numpy as np

try:
    import faiss
except Exception:
    faiss = None


class FaissVectorStore:
    def __init__(self, index_path, metadata_path):
        self.index_path = index_path
        self.metadata_path = metadata_path
        self.available = faiss is not None
        self.index = None
        self.dimension = 0
        self.records = []

    @property
    def count(self):
        return len(self.records)

    def load(self):
        if not self.available:
            return False

        loaded_any = False

        if os.path.exists(self.metadata_path):
            try:
                with open(self.metadata_path, "r", encoding="utf-8") as file_handle:
                    payload = json.load(file_handle)
                self.dimension = int(payload.get("dimension", 0) or 0)
                self.records = payload.get("records", [])
                loaded_any = True
            except Exception:
                self.dimension = 0
                self.records = []

        if os.path.exists(self.index_path):
            try:
                self.index = faiss.read_index(self.index_path)
                if self.index is not None:
                    self.dimension = int(self.index.d)
                    loaded_any = True
            except Exception:
                self.index = None

        if self.index is None and self.dimension > 0:
            self.index = faiss.IndexFlatIP(self.dimension)

        return loaded_any

    def add(self, vectors, texts, metadatas):
        if not self.available:
            return 0
        if vectors is None:
            return 0
        if len(texts) != len(metadatas):
            return 0
        if len(texts) == 0:
            return 0

        array = np.asarray(vectors, dtype=np.float32)
        if array.ndim == 1:
            array = array.reshape(1, -1)
        if array.shape[0] != len(texts):
            return 0

        array = self._normalize(array)
        dim = array.shape[1]
        if dim <= 0:
            return 0

        if self.index is None:
            self.dimension = dim
            self.index = faiss.IndexFlatIP(dim)

        if dim != self.dimension:
            return 0

        self.index.add(array)

        start_id = len(self.records)
        for offset, text in enumerate(texts):
            self.records.append(
                {
                    "id": start_id + offset,
                    "text": str(text),
                    "metadata": metadatas[offset],
                }
            )

        return len(texts)

    def search(self, query_vector, top_k=5):
        if not self.available or self.index is None:
            return []
        if self.index.ntotal <= 0:
            return []

        query = np.asarray(query_vector, dtype=np.float32)
        if query.ndim == 1:
            query = query.reshape(1, -1)

        if query.shape[1] != self.dimension:
            return []

        query = self._normalize(query)
        effective_top_k = max(int(top_k or 1), 1)
        distances, indices = self.index.search(query, effective_top_k)

        results = []
        for rank, idx in enumerate(indices[0]):
            if idx < 0 or idx >= len(self.records):
                continue
            record = self.records[idx]
            results.append(
                {
                    "id": record.get("id"),
                    "score": float(distances[0][rank]),
                    "text": record.get("text", ""),
                    "metadata": record.get("metadata", {}),
                }
            )
        return results

    def save(self):
        if not self.available:
            return False

        os.makedirs(os.path.dirname(self.metadata_path), exist_ok=True)
        payload = {
            "dimension": int(self.dimension or 0),
            "records": self.records,
        }
        with open(self.metadata_path, "w", encoding="utf-8") as file_handle:
            json.dump(payload, file_handle, indent=2)

        if self.index is not None:
            os.makedirs(os.path.dirname(self.index_path), exist_ok=True)
            faiss.write_index(self.index, self.index_path)

        return True

    @staticmethod
    def _normalize(vectors):
        if vectors.size == 0:
            return vectors
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return vectors / norms
