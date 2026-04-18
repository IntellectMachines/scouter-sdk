# Publishing `scouter-sdk`

This repo ships **two** packages from one monorepo:

| Ecosystem | Source dir | Package name      | Manifest                |
| --------- | ---------- | ----------------- | ----------------------- |
| PyPI      | `python/`  | `scouter-ai`      | `python/pyproject.toml` |
| npm       | `node/`    | `@scouter-ai/core` | `node/package.json`     |

Releases are automated by **`.github/workflows/publish.yml`** — creating a
GitHub Release publishes both packages in parallel.

---

## 1. One-time setup

### 1.1 Create publish tokens

- **PyPI**: <https://pypi.org/manage/account/token/> → create a token scoped to
  the `scouter-ai` project. The value starts with `pypi-`.
- **npm**: <https://www.npmjs.com/settings/<your-user>/tokens> → create an
  **Automation** token (bypasses 2FA in CI). Make sure your user has publish
  rights on the `@scouter` org/scope.

### 1.2 Register the secrets in GitHub

GitHub → **Settings → Secrets and variables → Actions → New repository secret**:

| Secret name      | Value                                   |
| ---------------- | --------------------------------------- |
| `PYPI_API_TOKEN` | The PyPI token from step 1.1            |
| `NPM_TOKEN`      | The npm automation token from step 1.1  |

See `.env.example` for the canonical list.

---

## 2. Releasing a new version

1. Make sure `master` is green.
2. On GitHub, **Releases → Draft a new release**.
3. Create a tag of the form `vX.Y.Z` (e.g. `v0.4.1`). The leading `v` is
   stripped by the workflow before being written into `pyproject.toml` /
   `package.json`, so the published version will be `X.Y.Z`.
4. Publish the release. The `Publish scouter-sdk` workflow runs:
   - `detect` job inspects which manifests exist
   - `publish-pypi` and `publish-npm` jobs run in parallel
   - Each job runs tests, bumps the version from the tag, builds, and publishes

> Pushes to `master` (no release) only run tests + builds — they never publish.

---

## 3. Manual deploy (fallback)

### 3.1 PyPI

```bash
cd python
python -m pip install --upgrade build twine
python -m build                       # produces dist/*.whl and dist/*.tar.gz
python -m twine check dist/*
python -m twine upload dist/*         # prompts for credentials
                                      # username: __token__
                                      # password: <PYPI_API_TOKEN>
```

### 3.2 npm

```bash
cd node
npm ci
npm test
npm run build
npm publish --access public           # requires `npm login` first
```

---

## 4. Troubleshooting

| Symptom                                                    | Likely cause / fix                                                                 |
| ---------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `403 Forbidden` from PyPI                                  | Token lacks scope for `scouter-ai`, or version already exists. Bump the tag.       |
| `npm ERR! 402 Payment Required`                            | Scoped package needs `--access public` (already in the workflow).                  |
| `npm ERR! 403 You do not have permission to publish`       | `NPM_TOKEN` user is not a member of the `@scouter` org with publish rights.        |
| Workflow says "PyPI job will be skipped"                   | `python/pyproject.toml` or `python/setup.py` is missing.                           |
| Workflow says "npm job will be skipped"                    | `node/package.json` is missing.                                                    |
| `File already exists` on PyPI upload                       | PyPI is immutable per version — bump the release tag and try again.                |

<!-- TODO: If you later add a Sigstore / OIDC trusted publisher on PyPI,
     replace the TWINE_PASSWORD step with `pypa/gh-action-pypi-publish@release/v1`
     using `permissions: id-token: write` and remove the PYPI_API_TOKEN secret. -->
