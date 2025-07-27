# Mudlet Functions with Network or Installation Side Effects

The scanner looks for Lua functions that may perform downloading, installation, or other network activity. These functions were identified from **Mudlet** documentation (stored in `docs/MudletDocs` when present) and are targeted because they can modify a user's system or communicate over the internet.

| Function | Purpose |
|----------|---------|
| `downloadFile(url, path)` | Downloads data from a URL to a local file. |
| `getHTTP(url)` | Performs an HTTP GET request. |
| `postHTTP(url, data)` | Sends an HTTP POST request. |
| `putHTTP(url, data)` | Sends an HTTP PUT request. |
| `deleteHTTP(url)` | Sends an HTTP DELETE request. |
| `customHTTP(opts)` | Performs a custom HTTP request with user-specified options. |
| `openWebPage(url)` | Opens a web page in the user's default browser. |
| `openUrl(url)` | Alias of `openWebPage`. |
| `installPackage(source)` | Installs a Mudlet package, optionally downloading it from a URL. |
| `uninstallPackage(name)` | Removes an installed Mudlet package. |
| `unzipAsync(zipfile, dest)` | Unpacks a zip archive asynchronously. |

Any package using these functions may warrant closer review, especially if they operate on external URLs or untrusted data.
