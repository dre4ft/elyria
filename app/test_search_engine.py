import playwright
from core.logging import get_logger
from core.config import get

_log = get_logger("ely.browser")



browsers = {}

def launch_browser():
    from playwright.sync_api import sync_playwright
    _log.info("Launching browser...")
    playwright_sync = sync_playwright().start()
    browser = playwright_sync.chromium.launch(headless=True)
    return browser

def close_browser(browser):
    _log.info("Closing browser...")
    browser.close()


def query_page(browser, url: str, selector: str = "body"):
    _log.info(f"Querying page: {url} with selector: {selector}")
    if url in get("security", "blocked_urls", []):
        _log.warning(f"URL {url} is blocked. Skipping browser query.")
        return ""
    context = browser.new_context()
    page = context.new_page()
    page.goto(url)
    content = page.query_selector(selector).inner_text() if page.query_selector(selector) else ""
    context.close()
    return content

def click_element(browser, url: str, selector: str):
    _log.info(f"Clicking element on page: {url} with selector: {selector}")
    if url in get("security", "blocked_urls", []):
        _log.warning(f"URL {url} is blocked. Skipping browser click.")
        return False
    context = browser.new_context()
    page = context.new_page()
    page.goto(url)
    element = page.query_selector(selector)
    if element:
        element.click()
        context.close()
        return True
    context.close()
    return False



def basic_handler(user_id: str, url: str = None,query: str = None, selector: str = "body", action: str = "query"):
    """Example of a basic browser interaction handler."""
    global browsers
    browser = browsers.get(user_id)
    if not browser:
        browser = launch_browser()
        browsers[user_id] = browser
    try:
        if action == "query":
            if not url:
                raise ValueError("URL is required for query action")
            content = query_page(browser, url, selector)
            _log.info(f"Queried page content for user {user_id}: {content[:100]}...")
            return content
        elif action == "click":
            if not url:
                raise ValueError("URL is required for click action")
            return click_element(browser, url, selector)
        else:
            _log.warning(f"Unknown browser action: {action}")
            raise ValueError(f"Unknown browser action: {action}")
    finally:
        close_browser(browser)



if __name__ == "__main__":
    # Example usage
    browser = launch_browser()
    content = query_page(browser, "https://google.com", "h1")
    print("Queried content:", content)
    close_browser(browser)