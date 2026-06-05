from request_manager.request_api import _make_request
from core.logging import get_logger

_log = get_logger("ely.search_engine")

def search_engine(query: str):
    raw_restults = _make_request(url=f"https://api.duckduckgo.com/?q={query}&format=json", method="GET")
    if not raw_restults:
        return "No results"
    try:
        data = raw_restults.get("data", {})
        results = data.get("RelatedTopics", [])
        formatted_results = []
        for item in results:
            if "Text" in item and "FirstURL" in item:
                formatted_results.append({"text": item["Text"], "url": item["FirstURL"]})
        return formatted_results
    except Exception as e:
        _log.error(f"Error parsing search results: {e}")
        return "Error parsing results"
    