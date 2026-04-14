import numpy as np


class TextEmbedder:
    def __init__(self, model_name, batch_size=32):
        self.model_name = model_name
        self.batch_size = max(int(batch_size or 1), 1)
        self._model = None
        self._error = ""
        self._cache = {}
        self._dimension = 0
        self._load_model()

    @property
    def available(self):
        return self._model is not None

    @property
    def error(self):
        return self._error

    @property
    def dimension(self):
        return self._dimension

    def _load_model(self):
        try:
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(self.model_name)
            get_dim = getattr(self._model, "get_embedding_dimension", None)
            if callable(get_dim):
                self._dimension = int(get_dim() or 0)
            else:
                self._dimension = int(self._model.get_sentence_embedding_dimension() or 0)
            self._error = ""
        except Exception as exc:
            self._model = None
            self._error = str(exc)
            self._dimension = 0

    def encode(self, texts):
        if not texts:
            return np.zeros((0, self._dimension), dtype=np.float32)

        clean_texts = [str(item or "").strip() for item in texts]
        if not self.available:
            return np.zeros((len(clean_texts), 0), dtype=np.float32)

        unique_to_embed = []
        for item in clean_texts:
            if item and item not in self._cache:
                unique_to_embed.append(item)

        if unique_to_embed:
            embeddings = self._model.encode(
                unique_to_embed,
                batch_size=self.batch_size,
                show_progress_bar=False,
                convert_to_numpy=True,
                normalize_embeddings=True,
            )
            embeddings = np.asarray(embeddings, dtype=np.float32)
            if embeddings.ndim == 1:
                embeddings = embeddings.reshape(1, -1)

            if embeddings.shape[1] > 0:
                self._dimension = embeddings.shape[1]

            for idx, text in enumerate(unique_to_embed):
                self._cache[text] = embeddings[idx]

        rows = []
        for item in clean_texts:
            if not item:
                rows.append(np.zeros((self._dimension,), dtype=np.float32))
                continue
            rows.append(self._cache[item])

        matrix = np.asarray(rows, dtype=np.float32)
        if matrix.ndim == 1:
            matrix = matrix.reshape(1, -1)
        return self._normalize(matrix)

    @staticmethod
    def _normalize(vectors):
        if vectors.size == 0:
            return vectors
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return vectors / norms
