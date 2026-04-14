import re


def _strip_tool_noise(text):
    cleaned_lines = []
    for raw_line in (text or "").splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()

        if not stripped:
            cleaned_lines.append("")
            continue

        if stripped.startswith(":: Progress:"):
            continue
        if stripped.startswith("________________________________________________"):
            continue
        if stripped.startswith("v2.1.0-dev"):
            continue

        cleaned_lines.append(line)

    return "\n".join(cleaned_lines)


def normalize_text(text):
    if not text:
        return ""

    text = str(text).replace("\r\n", "\n").replace("\r", "\n")
    text = _strip_tool_noise(text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r"[ \t]+", " ", text)
    return text.strip()


def chunk_text(text, min_words=200, max_words=500, overlap_words=60):
    cleaned = normalize_text(text)
    if not cleaned:
        return []

    if max_words < 50:
        max_words = 50
    if min_words < 20:
        min_words = 20
    if min_words > max_words:
        min_words = max_words
    if overlap_words < 0:
        overlap_words = 0

    words = cleaned.split()
    if len(words) <= max_words:
        return [cleaned]

    step = max(max_words - overlap_words, min_words)
    chunks = []

    for start in range(0, len(words), step):
        end = min(start + max_words, len(words))
        chunk_words = words[start:end]
        if not chunk_words:
            break

        if len(chunk_words) < min_words and chunks:
            chunks[-1] = f"{chunks[-1]} {' '.join(chunk_words)}".strip()
            break

        chunks.append(" ".join(chunk_words))

        if end >= len(words):
            break

    return [item.strip() for item in chunks if item.strip()]
