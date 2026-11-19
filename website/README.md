# Hermetic World website

A static, dependency-free site (plain HTML, CSS and JS). No build step.

## Publish on GitHub Pages

1. Push this folder and `.github/workflows/pages.yml` to `main`.
2. In the repo, go to **Settings → Pages → Build and deployment → Source** and choose **GitHub Actions**.
3. The workflow runs on every push that touches `website/`. The site appears at
   `https://shreenipane.github.io/HermeticWorld/` once the run finishes (Actions tab).

All asset paths are relative, so it works under the `/HermeticWorld/` project path and on a custom domain.

## Preview locally

```sh
cd website
python3 -m http.server 8000   # then open http://localhost:8000
```

## Edit

- `index.html` holds the content.
- `assets/css/styles.css` holds the design (light and dark follow the OS setting).
- `assets/js/main.js` drives the cutoff demo, the run stepper and the CLI tabs.
