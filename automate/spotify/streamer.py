#!/usr/bin/env python3
"""
Multithreaded Spotify Audio Streaming Script
Streams audio from a Spotify artist page using multiple browser instances
"""

import time
import threading
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, NoSuchElementException
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - Thread-%(thread)d - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SpotifyStreamer:
    """Handles streaming from a Spotify URL in a browser instance"""
    
    def __init__(self, url, thread_id, username=None, password=None):
        self.url = url
        self.thread_id = thread_id
        self.username = username
        self.password = password
        self.driver = None
        
    def setup_browser(self):
        """Configure and initialize the browser"""
        chrome_options = Options()
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-blink-features=AutomationControlled')
        chrome_options.add_argument('--disable-extensions')
        chrome_options.add_argument('--disable-plugins-discovery')
        chrome_options.add_argument('--disable-background-timer-throttling')
        chrome_options.add_argument('--disable-backgrounding-occluded-windows')
        chrome_options.add_argument('--disable-renderer-backgrounding')
        chrome_options.add_argument('--disable-ipc-flooding-protection')
        chrome_options.add_argument('--start-maximized')
        chrome_options.add_argument('--disable-web-security')
        chrome_options.add_argument('--allow-running-insecure-content')
        
        # Audio settings
        chrome_options.add_argument('--autoplay-policy=no-user-gesture-required')
        chrome_options.add_experimental_option('prefs', {
            'profile.default_content_setting_values.media_stream_mic': 1,
            'profile.default_content_setting_values.media_stream_camera': 1,
            'profile.default_content_setting_values.notifications': 2,
            'profile.default_content_setting_values.automatic_downloads': 1,
            'profile.default_content_setting_values.geolocation': 2,
            'profile.default_content_settings.popups': 0,
            'profile.managed_default_content_settings.images': 2  # Load images
        })
        
        # Remove automation flags
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        chrome_options.add_experimental_option('useAutomationExtension', False)
        
        # Add user agent to appear more like a real user
        chrome_options.add_argument('--user-agent=Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
        
        try:
            self.driver = webdriver.Chrome(options=chrome_options)
            
            # Execute scripts to remove webdriver property and make it look less like automation
            self.driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            self.driver.execute_script("window.chrome = { runtime: {} };")
            self.driver.execute_script("Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });")
            self.driver.execute_script("Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });")
            
            # Set window size that looks like a real user
            self.driver.set_window_size(1366, 768)
            
            logger.info(f"Thread {self.thread_id}: Browser initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Thread {self.thread_id}: Failed to initialize browser: {e}")
            return False
    
    def navigate_and_play(self):
        """Navigate to Spotify URL and attempt to play audio"""
        try:
            logger.info(f"Thread {self.thread_id}: Navigating to {self.url}")
            
            # Navigate to the URL
            self.driver.get(self.url)
            
            # Wait for page to load (with a timeout to avoid hanging)
            WebDriverWait(self.driver, 20).until(
                lambda driver: driver.execute_script("return document.readyState") == "complete"
            )
            
            # Add a random delay to appear more human-like
            import random
            time.sleep(random.uniform(2, 5))
            
            # Check if we're on a login page or if there's a login requirement
            current_url = self.driver.current_url
            if "accounts" in current_url or "login" in current_url or "auth" in current_url:
                logger.info(f"Thread {self.thread_id}: Redirected to login page. Need to be logged in to play music.")
                if self.username and self.password:
                    logger.info(f"Thread {self.thread_id}: Attempting to log in with credentials")
                    # Try to login if credentials are provided
                    self.login_to_spotify()
                else:
                    logger.warning(f"Thread {self.thread_id}: No login credentials provided, cannot play music")
                    return True  # Return True but indicate that music won't play without login
            
            # Handle potential login prompt by closing any login modals
            try:
                # Close any login modals that might appear
                close_buttons = [
                    "button[data-testid='x-circle-icon-button']",
                    "button[aria-label='Close']",
                    "button[aria-label='Dismiss']",
                    "button[class*='close']",
                    "div[data-testid='overlay'] button"
                ]
                
                for selector in close_buttons:
                    try:
                        close_button = WebDriverWait(self.driver, 3).until(
                            EC.element_to_be_clickable((By.CSS_SELECTOR, selector))
                        )
                        close_button.click()
                        logger.info(f"Thread {self.thread_id}: Closed modal with selector: {selector}")
                        time.sleep(random.uniform(1, 2))
                        break
                    except TimeoutException:
                        continue
            except Exception as e:
                logger.debug(f"Thread {self.thread_id}: No modal to close: {e}")
                pass  # No modal to close, continue
            
            # Wait a bit more for the page to fully load
            time.sleep(3)
            
            # Check if we're still on the artist page and try to play
            current_url = self.driver.current_url
            if "spotify.com/artist/" in current_url or "spotify.com/album/" in current_url or "spotify.com/playlist/" in current_url:
                # On artist/album/playlist pages, the main play button is usually a large play button to play all tracks
                # Multiple selectors to try in order of preference
                play_button_selectors = [
                    # Primary selectors for artist page (most common ones)
                    "[data-testid='play-button']",
                    "[aria-label='Play']",
                    "button[title='Play']",
                    "[data-testid='control-button-play']",
                    ".main-playButton-button",
                    "button.play",  # Simple class-based selector
                    # Fallback selectors
                    "button[data-button='play']",
                    ".play-button",
                    "button[class*='PlayButton']",
                    ".Button-sc-1dqy6lx-0.ButtonInner-sc-14ud5tc-0.gg4H9l",
                    # General fallback - any button that contains play text
                ]
                
                play_clicked = False
                for selector in play_button_selectors:
                    if play_clicked:
                        break
                    try:
                        # Wait for play button to be clickable
                        play_button = WebDriverWait(self.driver, 8).until(
                            EC.element_to_be_clickable((By.CSS_SELECTOR, selector))
                        )
                        if play_button.is_displayed() and play_button.is_enabled():
                            play_button.click()
                            logger.info(f"Thread {self.thread_id}: Play button clicked successfully with selector: {selector}")
                            play_clicked = True
                            # Wait a bit after clicking to let the player load
                            time.sleep(3)
                            break
                    except TimeoutException:
                        logger.debug(f"Thread {self.thread_id}: Selector {selector} timed out")
                        continue
                    except Exception as e:
                        logger.debug(f"Thread {self.thread_id}: Selector {selector} failed: {e}")
                        continue

                # If no primary selectors worked, try to find any play-related button with text
                if not play_clicked:
                    try:
                        # Look for buttons that might contain play text/meaning
                        all_buttons = self.driver.find_elements(By.TAG_NAME, "button")
                        for btn in all_buttons:
                            if btn.is_enabled() and btn.is_displayed():
                                btn_text = btn.text.strip().lower()
                                btn_aria = btn.get_attribute("aria-label")
                                btn_title = btn.get_attribute("title")
                                
                                # Check if the button is related to playing
                                is_play_button = (
                                    btn_text and ("play" in btn_text) or
                                    (btn_aria and "play" in btn_aria.lower()) or
                                    (btn_title and "play" in btn_title.lower())
                                )
                                
                                if is_play_button:
                                    btn.click()
                                    logger.info(f"Thread {self.thread_id}: Clicked play button found by text/attributes")
                                    play_clicked = True
                                    time.sleep(3)  # Wait after clicking
                                    break
                    except Exception as e:
                        logger.warning(f"Thread {self.thread_id}: Failed to find play button by text: {e}")

                if not play_clicked:
                    logger.warning(f"Thread {self.thread_id}: No play button could be found or clicked")
                    # Try to click on the first track if available
                    try:
                        # Look for the first track play button (on artist page)
                        first_track_selectors = [
                            ".tracklist-row .play-button",
                            "[data-testid='play-row'] button",
                            ".main-trackList-rowPlayButton",
                            ".play-button svg",
                            "button[aria-label*='Play'][aria-label*='track']"
                        ]
                        
                        for selector in first_track_selectors:
                            try:
                                first_track_btn = WebDriverWait(self.driver, 5).until(
                                    EC.element_to_be_clickable((By.CSS_SELECTOR, selector))
                                )
                                if first_track_btn.is_displayed() and first_track_btn.is_enabled():
                                    first_track_btn.click()
                                    logger.info(f"Thread {self.thread_id}: Played first track with selector: {selector}")
                                    play_clicked = True
                                    break
                            except TimeoutException:
                                continue
                    except:
                        pass  # Continue even if track playing fails
                else:
                    # Wait to see if playback actually starts
                    time.sleep(5)
                    if self.is_playing():
                        logger.info(f"Thread {self.thread_id}: Playback confirmed as active")
                    else:
                        logger.info(f"Thread {self.thread_id}: Play button clicked but playback might not start (requires Premium)")
            else:
                logger.info(f"Thread {self.thread_id}: Redirected to {current_url}, might be a login page or error")
            
            return True
            
        except Exception as e:
            logger.error(f"Thread {self.thread_id}: Error during navigation: {e}")
            return False
    
    def is_playing(self):
        """Check if audio is currently playing by looking for pause button"""
        try:
            # Look for pause button which indicates playing state
            pause_selectors = [
                "button[data-testid='pause-button']",
                "button[aria-label*='Pause']",
                "button[title*='Pause']",
                "button.main-pauseButton-button"
            ]
            
            for selector in pause_selectors:
                try:
                    pause_button = self.driver.find_element(By.CSS_SELECTOR, selector)
                    if pause_button:
                        return True
                except:
                    continue
            return False
        except:
            return False
    
    def login_to_spotify(self):
        """Attempt to log into Spotify if credentials are provided"""
        if not self.username or not self.password:
            # No credentials provided, just continue
            return True
        
        try:
            logger.info(f"Thread {self.thread_id}: Attempting to log in to Spotify")
            
            # Check if we're on the login page or if a login prompt appears
            login_selectors = [
                "input[type='email']",
                "input#login-username",
                "input[data-testid='login-username']",
                "input[name='username']",
                "button[data-testid='login-button']",
                "button[type='submit']"
            ]
            
            # Wait a bit for login elements to appear
            time.sleep(3)
            
            # Try to find and fill login credentials
            try:
                email_input = WebDriverWait(self.driver, 5).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='email'], input#login-username, input[data-testid='login-username'], input[name='username']"))
                )
                email_input.clear()
                email_input.send_keys(self.username)
                logger.info(f"Thread {self.thread_id}: Entered username")
            except TimeoutException:
                logger.info(f"Thread {self.thread_id}: No username field found, continuing")
            
            try:
                password_input = self.driver.find_element(By.CSS_SELECTOR, "input[type='password'], input#login-password, input[data-testid='login-password'], input[name='password']")
                password_input.clear()
                password_input.send_keys(self.password)
                logger.info(f"Thread {self.thread_id}: Entered password")
            except:
                logger.info(f"Thread {self.thread_id}: No password field found, continuing")
            
            # Try to click login button
            try:
                # Look for login buttons with specific attributes or text
                login_btn = None
                login_selectors = [
                    "button[data-testid='login-button']",
                    "button[type='submit']"
                ]
                
                for selector in login_selectors:
                    try:
                        login_btn = WebDriverWait(self.driver, 3).until(
                            EC.element_to_be_clickable((By.CSS_SELECTOR, selector))
                        )
                        break
                    except TimeoutException:
                        continue
                
                # If specific selectors don't work, try to find buttons with login text
                if not login_btn:
                    all_buttons = self.driver.find_elements(By.TAG_NAME, "button")
                    for btn in all_buttons:
                        btn_text = btn.text.lower()
                        if "log in" in btn_text or "sign in" in btn_text or "login" in btn_text:
                            if btn.is_enabled() and btn.is_displayed():
                                login_btn = btn
                                break
                
                if login_btn:
                    login_btn.click()
                    logger.info(f"Thread {self.thread_id}: Clicked login button")
                    time.sleep(3)  # Wait for login to process
                else:
                    logger.info(f"Thread {self.thread_id}: No login button found")
            except:
                logger.info(f"Thread {self.thread_id}: No login button found or error occurred")
            
            # Wait for potential 2FA or for login to complete
            time.sleep(5)
            
            return True
            
        except Exception as e:
            logger.warning(f"Thread {self.thread_id}: Login failed (this may be normal if already logged in): {e}")
            return True  # Continue anyway since login might not be required
    
    def stream(self, duration=None):
        """
        Stream audio for specified duration
        
        Args:
            duration: Time in seconds to stream (None = indefinite)
        """
        if not self.setup_browser():
            return False
        
        # Attempt to login if credentials are provided
        self.login_to_spotify()
        
        if not self.navigate_and_play():
            self.cleanup()
            return False
        
        logger.info(f"Thread {self.thread_id}: Streaming started")
        
        try:
            if duration:
                logger.info(f"Thread {self.thread_id}: Streaming for {duration} seconds")
                time.sleep(duration)
            else:
                logger.info(f"Thread {self.thread_id}: Streaming indefinitely (press Ctrl+C to stop)")
                while True:
                    time.sleep(10)
                    
                    # Check if browser is still alive and responsive
                    try:
                        # Attempt a simple operation to check browser responsiveness
                        # If this fails, the browser session is likely dead
                        self.driver.execute_script("return true;")
                        
                        # Check if current URL is still the expected Spotify page
                        current_url = self.driver.current_url
                        if not current_url or "error" in current_url.lower() or "sorry" in current_url.lower() or "unsupported" in current_url.lower():
                            logger.warning(f"Thread {self.thread_id}: Invalid page detected, URL: {current_url}")
                            break
                    except:
                        logger.warning(f"Thread {self.thread_id}: Browser session ended or unresponsive")
                        break
                        
        except KeyboardInterrupt:
            logger.info(f"Thread {self.thread_id}: Streaming interrupted by user")
        except Exception as e:
            logger.error(f"Thread {self.thread_id}: Error during streaming: {e}")
        finally:
            self.cleanup()
        
        return True
    
    def cleanup(self):
        """Close the browser and cleanup resources"""
        if self.driver:
            try:
                self.driver.quit()
                logger.info(f"Thread {self.thread_id}: Browser closed successfully")
            except Exception as e:
                logger.error(f"Thread {self.thread_id}: Error during cleanup: {e}")


def stream_worker(url, thread_id, duration=None, username=None, password=None):
    """Worker function for threading"""
    streamer = SpotifyStreamer(url, thread_id, username, password)
    streamer.stream(duration)


def main():
    """Main function to orchestrate multithreaded streaming"""
    
    # Configuration
    SPOTIFY_URL = "https://open.spotify.com/artist/4nuhvrxSfrrx8QBkJXRT3j"
    NUM_THREADS = 3  # Number of concurrent browser instances
    STREAM_DURATION = None  # None = indefinite, or specify seconds
    # Spotify login credentials (set to None if not needed)
    # NOTE: For automated playback, you need a Spotify Premium account
    SPOTIFY_USERNAME = None  # Set your Spotify username/email here if needed
    SPOTIFY_PASSWORD = None  # Set your Spotify password here if needed
    
    logger.info(f"Starting Spotify streaming with {NUM_THREADS} threads")
    logger.info(f"Target URL: {SPOTIFY_URL}")
    if SPOTIFY_USERNAME:
        logger.info("Using Spotify credentials for login")
    else:
        logger.info("No Spotify credentials provided - music may not play without Premium account")
    
    # Create and start threads
    threads = []
    
    try:
        for i in range(NUM_THREADS):
            thread = threading.Thread(
                target=stream_worker,
                args=(SPOTIFY_URL, i+1, STREAM_DURATION, SPOTIFY_USERNAME, SPOTIFY_PASSWORD),
                name=f"Streamer-{i+1}"
            )
            thread.start()
            threads.append(thread)
            
            # Stagger the thread starts to avoid overwhelming the system
            time.sleep(2)
        
        # Wait for all threads to complete
        logger.info("All threads started. Waiting for completion...")
        for thread in threads:
            thread.join()
        
        logger.info("All streaming threads completed")
        
    except KeyboardInterrupt:
        logger.info("\nReceived interrupt signal. Waiting for threads to cleanup...")
        for thread in threads:
            thread.join(timeout=5)
        logger.info("Cleanup complete")
    except Exception as e:
        logger.error(f"Error in main thread: {e}")


if __name__ == "__main__":
    print("""
    ╔═══════════════════════════════════════════════════════╗
    ║     Multithreaded Spotify Audio Streamer            ║
    ║                                                       ║
    ║  This script will open multiple browser instances    ║
    ║  and stream audio from the specified Spotify page    ║
    ║                                                       ║
    ║  NOTE: Spotify requires a Premium account for        ║
    ║        automated playback. Free accounts will not    ║
    ║        play music automatically.                     ║
    ║                                                       ║
    ║  Press Ctrl+C to stop all streams                    ║
    ╚═══════════════════════════════════════════════════════╝
    """)
    
    main()
