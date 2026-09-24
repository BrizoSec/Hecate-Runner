import logging

log = logging.getLogger(__name__)

def measure_tokens(text: str, model_name: str = "gpt-4") -> int:
    """Measure the token usage of a text payload to help optimize context window sizing."""
    if not text:
        return 0
    try:
        import tiktoken
        # Fall back to cl100k_base (gpt-4) if the specific model isn't known to tiktoken
        try:
            encoding = tiktoken.encoding_for_model(model_name)
        except KeyError:
            encoding = tiktoken.get_encoding("cl100k_base")
            
        count = len(encoding.encode(text))
        return count
    except ImportError:
        log.warning("tiktoken not installed, skipping context measurement.")
        return 0
    except Exception as e:
        log.warning("Failed to measure context token usage: %s", e)
        return 0
