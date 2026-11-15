# Permissions for the Browser Extension

```json
{
  "manifest_version": 3,
  "name": "DIDSSO-Extension",
  "version": "1.0.0",
  "permissions": [
    "storage",
    "webRequest",
    "webRequestBlocking",
    "tabs"
  ],
  "host_permissions": [
    "http://127.0.0.1/*",
    "https://127.0.0.1/*",
    "http://127.0.0.1:8765/*"
  ],
  "background": {
    "scripts": ["background.js"]
  }
}
```

## `storage`

Allows the extension to store data in the browser.

This can be used to store configuration values, detected requests, tokens, state information, or analysis results. In JavaScript, this is usually done with `browser.storage.local`.

## `webRequest`

Allows the extension to observe browser network requests.

This lets the extension read information about requests, for example:

- URL
- HTTP method, such as `GET` or `POST`
- request type, such as `main_frame`, `script`, `image`, or `xmlhttprequest`
- Header
- status and errors
- timestamp of the request

This permission is enough if the extension only needs to analyze or log requests.

## `webRequestBlocking`

Allows the extension to actively interfere with requests.

This can be used to:

- block requests
- redirect requests
- modify request headers
- modify response headers
- trigger actions under certain conditions before a request continues

This permission is required if the extension should not only observe communication, but also act on it directly.

## `tabs`

Allows access to information about browser tabs.

This is useful when requests need to be linked to a specific tab or website. Without this permission, the extension can still see requests, but it gets less context about the tab.

## `host_permissions`

The current Manifest Version 3 extension is restricted to HTTP and HTTPS
services at `127.0.0.1`, including the local user backend on port 8765. It does
not request `<all_urls>` access. The JSON above shows the relevant permission
and background-script fields; the complete manifest also configures the popup
and Firefox extension identifier.

Host permissions allow observation of the local prototype traffic. Within that
scope, `background.js` adds DID headers only to POST requests to `/sso/start`
and `/did-login/start`. Generic registration requests are not modified.

Deployment at other addresses would require adapting both the host permissions
and the local-address checks in the request handlers.

## Important Note

With `webRequest`, the extension is not a full network sniffer. It can see browser requests for which it has the required host permissions. Depending on the API and browser, it can process URLs, headers, status information, and in some cases response data.

Because these permissions are very sensitive, the extension should only store and process the data that is truly necessary for its functionality.
