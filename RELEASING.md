# Releasing MProxy

1. Choose the new version, for example `1.0.0`.
2. Update both `extension/manifest.json` and `runtime/VERSION.txt` to that version.
3. Test the extension with the runtime installed on Windows.
4. Create these archives (their contents must be at the root of each ZIP):
   - `MProxy-extension-v<version>.zip` from the contents of `extension/`
   - `MProxy-runtime-windows-v<version>.zip` from the contents of `runtime/`
5. Commit the version change and tag it with `v<version>`.
6. Push `main` and the tag to GitHub.
7. Create a GitHub Release from that tag and attach both ZIP files.

Keep `runtime/LICENSES/` in the runtime archive. Do not upload a release until you
have confirmed that it contains no private proxy configuration or credentials.
