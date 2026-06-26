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
    launch_args = {"headless": True}
    from core.proxy import get_current_proxy_url
    proxy_url = get_current_proxy_url()
    if proxy_url:
        launch_args["proxy"] = {"server": proxy_url}
        _log.info(f"Browser using proxy: {proxy_url}")
    browser = await playwright.chromium.launch(**launch_args)
    return browser, playwright

async def close_browser(browser, playwright):
    """Version async de fermeture"""
    _log.info("Closing browser...")
    await browser.close()
    await playwright.stop()

async def query_page(browser, url: str, selector: str = "body", timeout: int = 15000):
    _log.info(f"Querying page: {url} with selector: {selector}")
    if url in get("security", "blocked_urls", []):
        _log.warning(f"URL {url} is blocked. Skipping browser query.")
        return ""
    context = await browser.new_context()
    try:
        page = await context.new_page()
        await page.goto(url, timeout=timeout)
        loc = page.locator(selector).first
        content = await loc.inner_text() if await loc.count() > 0 else ""
        return content
    finally:
        await context.close()

async def click_element(browser, url: str, selector: str, timeout: int = 15000):
    _log.info(f"Clicking element on page: {url} with selector: {selector}")
    if url in get("security", "blocked_urls", []):
        _log.warning(f"URL {url} is blocked. Skipping browser click.")
        return False
    context = await browser.new_context()
    try:
        page = await context.new_page()
        await page.goto(url, timeout=timeout)
        loc = page.locator(selector).first
        if await loc.count() > 0:
            await loc.click()
            return True
        return False
    finally:
        await context.close()

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
        # Clean up on error
        if user_id in browsers:
            try:
                await close_browser(browser, playwright)
            except Exception:
                pass
            del browsers[user_id]
        if action == "query":
            return f"Error: {e}"
        raise e 