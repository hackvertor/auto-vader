![](https://github.com/hackvertor/auto-vader/blob/main/src/main/resources/images/logo.png)

# AutoVader

AutoVader is a Burp Suite extension that integrates DOM Invader with Playwright Java to automatically find DOM-based vulnerabilities in web applications. It provides automated scanning capabilities through context menu actions, allowing security testers to quickly identify client-side security issues without manual DOM Invader interaction.

## Installation

In Burp Suite Professional, go to Extensions->BApp store and search for AutoVader. Click the install button.

## Requirements

- Burp Suite Professional (required for DOM Invader)
- DOM Invader extension (automatically detected from Burp installation)

## How to Use

AutoVader adds a context menu to Burp Suite with multiple scanning options. Right-click on any request in the Target, Proxy History, or Repeater tabs to access AutoVader features.

### Available Scans

**Open DOM Invader**
- Opens a browser with DOM Invader configured for manual testing
- Useful for debugging or custom analysis

**Scan all GET params**
- Automatically enumerates all query parameters
- Injects canary values into each parameter
- Detects DOM-based vulnerabilities from URL inputs

**Scan all POST params**
- Automatically enumerates all POST parameters
- Injects canary values into each parameter
- Detects DOM-based vulnerabilities from POST inputs

**Scan web messages**
- Tests for postMessage vulnerabilities
- Spoofs origins and attempts message injection
- Identifies unsafe message handlers

**Inject into all sources**
- Systematically injects payloads into all identified sources
- Tests for DOM XSS through various input vectors

**Inject into all sources & click everything**
- Same as above but also triggers click events
- Useful for finding vulnerabilities in event handlers

**Scan for client side prototype pollution**
- Detects prototype pollution vulnerabilities
- Tests query string, hash, and JSON inputs
- Verifies pollution with automated checks

**Scan for client side prototype pollution gadgets**
- Discovers exploitable gadgets for prototype pollution
- Identifies dangerous property assignments

**Intercept client side redirect**
- Sets breakpoints on client-side redirects
- Helps identify open redirect vulnerabilities

### Settings

AutoVader provides project-specific settings accessible through Burp Suite's Settings:

- **Path to DOM Invader**: Allows you to overwrite the DOM Invader path if auto-detection fails.
- **Path to Burp Chromium**: Allows you to overwrite the Chromium path to the executable if auto-detection fails.
- **Payload**: Custom payload to append to canary values when scanning
- **Delay**: Delay between requests
- **Always open devtools**: Each time the browser window is open the devtools panel will be shown
- **Remove CSP**: Removes Content-Security-Policy headers to ensure DOM Invader functions correctly (enabled by default)

### How It Works

1. AutoVader uses Playwright to launch a headless Chromium browser with DOM Invader extension
2. It automatically configures DOM Invader settings based on the selected scan type
3. The browser navigates to target URLs with appropriate payloads
4. DOM Invader findings are captured via callbacks and reported as Burp issues
5. Issues are deduplicated to prevent duplicate findings

### Features

- **Automated DOM vulnerability scanning** - No manual DOM Invader interaction needed
- **Multiple scan profiles** - Optimized settings for different vulnerability types
- **Issue deduplication** - Prevents duplicate findings across scans
- **Project-specific canaries** - Unique identifiers per Burp project
- **Burp integration** - Reports findings directly as Burp Scanner issues
- **Configurable payloads** - Customize injection payloads via settings

## Technical Details

AutoVader leverages:
- **Playwright Java** for browser automation
- **DOM Invader** for vulnerability detection
- **Burp Montoya API** for extension integration

The extension automatically detects Burp's bundled Chromium installation and DOM Invader extension paths, requiring no manual configuration.

## Author

Created by Gareth Heyes

## Support

For issues, feature requests, or questions, please open an issue on the GitHub repository.