"""Deterministic monthly term inventory and reader, without a ranking engine.

This versioned interchange format prepares a frozen corpus for the planned
tantivy integration. lookup_terms returns URL-ordered conjunctive candidates;
it is not the architecture's BM25 search service. Tokenization is explicitly
ASCII alphanumeric, independent of Unicode tables, locale or host settings.
"""

import re

from hermetic_npm_cut.cut import HermeticNpmCutError, read_regular_file_bounded
from hermetic_safe_io import validate_path

from . import formats as f

MAX_TITLE_BYTES = 512
MAX_TERM_BYTES = 64
MAX_DOCUMENT_TOKENS = 32768
MAX_TOTAL_TOKENS = 262144
MAX_TERMS = 32768
MAX_QUERY_BYTES = 1024
MAX_QUERY_TERMS = 32
MAX_RESULTS = 100
TOKENIZER = "ascii-alnum-lower/v1"
SCHEMA = "hermetic-search-index/v1"
RECORD_FIELDS = {"url", "captured", "source", "record_sha256", "text_sha256", "title"}
INDEX_FIELDS = {"schema", "month", "tokenizer", "documents", "terms"}


def _month(value) -> int:
    if type(value) is not str or re.fullmatch(r"[0-9]{4}-[0-9]{2}", value) is None:
        raise f.ArchiveError("invalid search month")
    return f.timestamp(value + "-01T00:00:00Z")


def _title(value) -> None:
    if (type(value) is not str or len(value) > MAX_TITLE_BYTES
            or len(value.encode("utf-8")) > MAX_TITLE_BYTES
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise f.ArchiveError("invalid search title")


def _tokens(text: str, cap: int):
    for count, match in enumerate(re.finditer(r"[A-Za-z0-9]+", text), start=1):
        term = match.group()
        if count > cap or len(term) > MAX_TERM_BYTES:
            raise f.ArchiveError("search token count or size cap exceeded")
        yield term.lower()


def build_search_index(raw_recipe: bytes, blobs: dict[str, bytes]) -> bytes:
    recipe = f.document(raw_recipe, {"schema", "month", "documents"})
    if recipe["schema"] != "hermetic-search-recipe/v1":
        raise f.ArchiveError("unsupported search recipe schema")
    boundary = _month(recipe["month"])
    entries = f.captures(recipe["documents"], RECORD_FIELDS)
    for entry in entries:
        _title(entry["title"])
        if type(entry["source"]) is not str or entry["source"] not in f.SOURCES:
            raise f.ArchiveError("invalid search source")
        f.digest(entry["record_sha256"])
        f.digest(entry["text_sha256"])
    blobs = f.payloads(blobs, {entry["text_sha256"] for entry in entries})
    selected = {}
    total_tokens = 0
    for entry in entries:
        try:
            text = blobs[entry["text_sha256"]].decode("utf-8")
        except UnicodeDecodeError:
            raise f.ArchiveError("invalid search text encoding") from None
        frequencies = {}
        for term in _tokens(entry["title"] + "\n" + text, MAX_DOCUMENT_TOKENS):
            total_tokens += 1
            if total_tokens > MAX_TOTAL_TOKENS:
                raise f.ArchiveError("search aggregate token cap exceeded")
            frequencies[term] = frequencies.get(term, 0) + 1
        date = f.timestamp(entry["captured"])
        previous = selected.get(entry["url"])
        # Strictly before the first day, even for a cutoff later in the month.
        if date < boundary and (previous is None or date > f.timestamp(previous[0]["captured"])):
            selected[entry["url"]] = (entry, frequencies)
    documents = []
    terms = {}
    for key in sorted(selected):
        entry, frequencies = selected[key]
        doc_id = len(documents)
        documents.append(dict(entry, length=sum(frequencies.values())))
        for term in sorted(frequencies):
            terms.setdefault(term, []).append([doc_id, frequencies[term]])
            if len(terms) > MAX_TERMS:
                raise f.ArchiveError("search term inventory cap exceeded")
    return f.bounded_encoding({"schema": SCHEMA, "month": recipe["month"], "tokenizer": TOKENIZER,
                               "documents": documents,
                               "terms": [[term, terms[term]] for term in sorted(terms)]})


class SearchIndex:
    def __init__(self, raw_index: bytes, expected_sha256: str, month: str):
        boundary = _month(month)
        value = f.authenticated(raw_index, expected_sha256, INDEX_FIELDS)
        if value["schema"] != SCHEMA or value["month"] != month or value["tokenizer"] != TOKENIZER:
            raise f.ArchiveError("search index policy mismatch")
        documents = f.captures(value["documents"], RECORD_FIELDS | {"length"})
        urls = [entry["url"] for entry in documents]
        if urls != sorted(set(urls)):
            raise f.ArchiveError("invalid search document order")
        total = 0
        for entry in documents:
            _title(entry["title"])
            f.digest(entry["record_sha256"])
            f.digest(entry["text_sha256"])
            if (type(entry["source"]) is not str or entry["source"] not in f.SOURCES
                    or f.timestamp(entry["captured"]) >= boundary
                    or type(entry["length"]) is not int
                    or not 0 <= entry["length"] <= MAX_DOCUMENT_TOKENS):
                raise f.ArchiveError("invalid search document admission or length")
            total += entry["length"]
        if total > MAX_TOTAL_TOKENS:
            raise f.ArchiveError("search aggregate token cap exceeded")
        terms = value["terms"]
        if type(terms) is not list or len(terms) > MAX_TERMS:
            raise f.ArchiveError("invalid search term inventory")
        previous = ""
        lengths = [0 for _ in documents]
        postings = {}
        posting_count = 0
        for pair in terms:
            if type(pair) is not list or len(pair) != 2:
                raise f.ArchiveError("invalid search term record")
            term, rows = pair
            if (type(term) is not str or not 0 < len(term) <= MAX_TERM_BYTES
                    or re.fullmatch(r"[a-z0-9]+", term) is None or term <= previous
                    or type(rows) is not list or not rows or len(rows) > len(documents)):
                raise f.ArchiveError("invalid search term or postings")
            previous = term
            last_id = -1
            ids = []
            for row in rows:
                posting_count += 1
                if posting_count > MAX_TOTAL_TOKENS or type(row) is not list or len(row) != 2:
                    raise f.ArchiveError("invalid search posting count or record")
                doc_id, frequency = row
                if (type(doc_id) is not int or not last_id < doc_id < len(documents)
                        or type(frequency) is not int or not 0 < frequency <= MAX_DOCUMENT_TOKENS):
                    raise f.ArchiveError("invalid search posting reference or frequency")
                # Both indices are bounded above, and negative/bool ids refused.
                lengths[doc_id] += frequency
                if lengths[doc_id] > MAX_DOCUMENT_TOKENS:
                    raise f.ArchiveError("search document token cap exceeded")
                ids.append(doc_id)
                last_id = doc_id
            postings[term] = frozenset(ids)
        if lengths != [entry["length"] for entry in documents]:
            raise f.ArchiveError("search document length mismatch")
        self._urls = tuple(urls)
        self._postings = postings

    def lookup_terms(self, query: str, limit: int = MAX_RESULTS) -> tuple[str, ...]:
        if (type(query) is not str or len(query) > MAX_QUERY_BYTES
                or type(limit) is not int or not 0 <= limit <= MAX_RESULTS):
            raise f.ArchiveError("invalid search query or result cap")
        try:
            if len(query.encode("utf-8")) > MAX_QUERY_BYTES:
                raise f.ArchiveError("search query byte cap exceeded")
        except UnicodeEncodeError:
            raise f.ArchiveError("invalid search query encoding") from None
        terms = set(_tokens(query, MAX_QUERY_TERMS))
        if not terms or limit == 0:
            return ()
        candidates = None
        for term in sorted(terms):
            ids = self._postings.get(term, frozenset())
            candidates = ids if candidates is None else candidates & ids
        return tuple(self._urls[doc_id] for doc_id in sorted(candidates))[:limit]


def load_search_file(index_path, expected_sha256: str, month: str) -> SearchIndex:
    """Load one bounded index from an inspected, descriptor-pinned regular file."""
    try:
        f.digest(expected_sha256)
        _month(month)
        validate_path(index_path)
        raw = read_regular_file_bounded(index_path, f.MAX_INDEX_BYTES)
        return SearchIndex(raw, expected_sha256, month)
    except (OSError, ValueError, TypeError, HermeticNpmCutError):
        raise f.ArchiveError("search index file load failed") from None
