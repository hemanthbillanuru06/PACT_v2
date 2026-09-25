"""Semantic Search and Case Similarity Engine with In-Memory Model Caching.

Uses sentence-transformers ('all-MiniLM-L6-v2') cached in-memory, with seamless
TF-IDF vectorizer fallback via scikit-learn.
"""
import logging
from typing import List, Dict, Any, Optional, Union
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from config.settings import settings

logger = logging.getLogger("pact.services.semantic_search")

# Model Singleton Cache
_MODEL_CACHE: Optional[Any] = None
_MODEL_FAILED: bool = False


class SemanticSearchEngine:
    """Manages sentence embedding model caching and similarity computation."""

    @classmethod
    def get_model(cls) -> Optional[Any]:
        """Retrieve cached SentenceTransformer instance or load once into memory."""
        global _MODEL_CACHE, _MODEL_FAILED

        if _MODEL_CACHE is not None:
            return _MODEL_CACHE

        if _MODEL_FAILED:
            return None

        try:
            from sentence_transformers import SentenceTransformer
            logger.info("Loading '%s' embedding model into memory cache...", settings.EMBEDDING_MODEL_NAME)
            _MODEL_CACHE = SentenceTransformer(settings.EMBEDDING_MODEL_NAME)
            logger.info("Model '%s' successfully cached in memory.", settings.EMBEDDING_MODEL_NAME)
            return _MODEL_CACHE
        except Exception as err:
            logger.warning(
                "SentenceTransformer load failed (%s). Falling back to TF-IDF vectorizer: %s",
                settings.EMBEDDING_MODEL_NAME, err
            )
            _MODEL_FAILED = True
            return None

    @classmethod
    def encode_texts(cls, texts: List[str]) -> np.ndarray:
        """Encode a list of text strings into vector representations."""
        if not texts:
            return np.empty((0, 384))

        model = cls.get_model()
        if model is not None:
            try:
                embeddings = model.encode(texts, convert_to_numpy=True, show_progress_bar=False)
                return embeddings
            except Exception as err:
                logger.error("SentenceTransformer encoding failed: %s. Using TF-IDF fallback.", err)

        # Fallback: TF-IDF
        vectorizer = TfidfVectorizer(stop_words="english", max_features=1000)
        tfidf_matrix = vectorizer.fit_transform(texts)
        return tfidf_matrix.toarray()

    @classmethod
    def find_potentially_similar_cases(
        cls,
        target_case_or_text: Union[Dict[str, Any], str],
        candidate_cases: List[Dict[str, Any]],
        top_k: int = 5,
        min_threshold: float = 0.20,
    ) -> List[Dict[str, Any]]:
        """Find potentially similar cases based on crime type, description, and Modus Operandi.

        CRITICAL POLICE COMPLIANCE:
        Flag results as 'Potentially Similar Cases (Pending Corroboration)' and NEVER
        declare them as 'confirmed connections'.
        """
        if not candidate_cases:
            return []

        # Determine target case ID to exclude self-comparison
        target_id = None
        if isinstance(target_case_or_text, dict):
            target_id = target_case_or_text.get("case_id")
            query_text = (
                f"{target_case_or_text.get('crime_type', '')}. "
                f"{target_case_or_text.get('title', '')}. "
                f"{target_case_or_text.get('summary', '')}. "
                f"Modus Operandi: {target_case_or_text.get('modus_operandi', '')}"
            ).strip()
        else:
            query_text = str(target_case_or_text).strip()

        # Build candidate corpus
        valid_candidates = []
        corpus_texts = []

        for c in candidate_cases:
            if target_id and c.get("case_id") == target_id:
                continue  # Skip self
            text_rep = (
                f"{c.get('crime_type', '')}. "
                f"{c.get('title', '')}. "
                f"{c.get('summary', '')}. "
                f"Modus Operandi: {c.get('modus_operandi', '')}"
            ).strip()
            valid_candidates.append(c)
            corpus_texts.append(text_rep)

        if not valid_candidates:
            return []

        all_texts = [query_text] + corpus_texts
        model = cls.get_model()
        engine_used = "sentence-transformers" if model is not None else "tfidf-fallback"

        try:
            embeddings = cls.encode_texts(all_texts)
            query_vector = embeddings[0:1]
            candidate_vectors = embeddings[1:]

            # Compute Cosine Similarity
            sim_scores = cosine_similarity(query_vector, candidate_vectors)[0]

            ranked_indices = np.argsort(sim_scores)[::-1]
            matches = []

            for idx in ranked_indices:
                score = float(sim_scores[idx])
                if score < min_threshold and len(matches) >= top_k:
                    break

                cand = valid_candidates[idx]
                matches.append({
                    "case_id": cand.get("case_id"),
                    "title": cand.get("title"),
                    "crime_type": cand.get("crime_type"),
                    "station_id": cand.get("station_id"),
                    "status": cand.get("status"),
                    "priority": cand.get("priority"),
                    "io_officer_id": cand.get("io_officer_id"),
                    "modus_operandi": cand.get("modus_operandi", "N/A"),
                    "similarity_score": round(score, 4),
                    "engine_used": engine_used,
                    "disclaimer": "Potentially Similar Case (Pending Corroboration) - Not Confirmed Connection",
                })

                if len(matches) >= top_k:
                    break

            return matches

        except Exception as err:
            logger.error("Semantic similarity comparison error: %s", err)
            return []
