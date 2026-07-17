# Permissions for the Browser Extension

```json
{
  "manifest_version": 2,
  "name": "DIDSSO Browser Extension",
  "version": "1.0.0",
  "permissions": [
    "storage",
    "webRequest",
    "webRequestBlocking",
    "tabs",
    "<all_urls>"
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

## `<all_urls>`

Allows the extension to access requests from all websites.

This is very broad. It is useful during development and testing, but for a real extension the permission should be restricted as much as possible.

Instead of:

```json
"<all_urls>"
```

you can specify targeted domains:

```json
"https://example.com/*"
```

or multiple domains:

```json
[
  "https://example.com/*",
  "https://api.example.com/*"
]
```

## Important Note

With `webRequest`, the extension is not a full network sniffer. It can see browser requests for which it has the required host permissions. Depending on the API and browser, it can process URLs, headers, status information, and in some cases response data.

Because these permissions are very sensitive, the extension should only store and process the data that is truly necessary for its functionality.
