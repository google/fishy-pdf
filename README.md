# FishyPDF

FishyPDF is a viewer and analyzer for inspecting suspicious PDF files.

It is based heavily on [Mozilla's PDF.js](https://github.com/mozilla/pdf.js)
with more secure defaults and some additional analysis features added.

## Code structure

Since this project is a modified version of the original PDF.js web viewer, some
of the code is hard to cleanly separate.

The directory `third_party/pdfjs/` contains a copy of the PDF.js distribution bundle ([pdfjs-3.10.111-dist.zip](https://github.com/mozilla/pdf.js/releases/tag/v3.10.111)) with the following changes:

 - changes to `viewer.html` (original preserved in `viewer.html.original`)
 - removed the example file (`web/compressed.tracemonkey-pldi-09.pdf`)
 - new files added in `web-customizations/` (including a vue release bundle under a separate license in `third_party/vue`)
 - added a `_headers` file for Cloudflare or similar and a redirecting `index.html`

The `third_party/pdfjs/` directory is intended to serve as the webroot.

`pdfjs-server.py` can be used to serve the webroot locally with CSP headers.

To make it easier to pull in new versions of pdf.js, changes should be kept
separate as far as possible (i.e. add new files in `web-customizations` or above
the `third_party directory` unless they need to be elsewhere for technical
reasons, try to avoid making changes to files from the pdf.js distribution
bundle with the exception of `viewer.html`).

## Disclaimer

This is not an officially supported Google product.
