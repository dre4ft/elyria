# browser.py - Version asynchrone
from core.logging import get_logger
from core.config import get
from playwright.async_api import async_playwright

_log = get_logger("ely.browser")

browsers = {}

async def launch_browser():
    """Version async de lancement du browser"""
    _log.info("Launching browser (async)...")
    playwright = await async_playwright().start()
    browser = await playwright.chromium.launch(headless=True)
    # Stocker aussi playwright pour pouvoir le fermer
    return browser, playwright

async def close_browser(browser, playwright):
    """Version async de fermeture"""
    _log.info("Closing browser...")
    await browser.close()
    await playwright.stop()

async def query_page(browser, url: str, selector: str = "body"):
    _log.info(f"Querying page: {url} with selector: {selector}")
    if url in get("security", "blocked_urls", []):
        _log.warning(f"URL {url} is blocked. Skipping browser query.")
        return ""
    context = await browser.new_context()
    page = await context.new_page()
    await page.goto(url)
    element = await page.query_selector(selector)
    content = await element.inner_text() if element else ""
    await context.close()
    return content

async def click_element(browser, url: str, selector: str):
    _log.info(f"Clicking element on page: {url} with selector: {selector}")
    if url in get("security", "blocked_urls", []):
        _log.warning(f"URL {url} is blocked. Skipping browser click.")
        return False
    context = await browser.new_context()
    page = await context.new_page()
    await page.goto(url)
    element = await page.query_selector(selector)
    if element:
        await element.click()
        await context.close()
        return True
    await context.close()
    return False

async def basic_handler(user_id: str, url: str = None, selector: str = "body", action: str = "query"):
    """Handler asynchrone pour les opérations browser"""
    global browsers
    
    # Stocker un tuple (browser, playwright)
    if user_id not in browsers:
        browser, playwright = await launch_browser()
        browsers[user_id] = (browser, playwright)
    else:
        browser, playwright = browsers[user_id]
    
    try:
        if action == "query":
            if not url:
                raise ValueError("URL required")
            return await query_page(browser, url, selector)
        elif action == "click":
            if not url:
                raise ValueError("URL required")
            return await click_element(browser, url, selector)
        elif action == "close":
            await close_browser(browser, playwright)
            del browsers[user_id]
            return True
    except Exception as e:
        _log.error(f"Browser action failed: {e}")
        # Nettoyer en cas d'erreur
        if user_id in browsers:
            await close_browser(browser, playwright)
            del browsers[user_id]
        raise e 