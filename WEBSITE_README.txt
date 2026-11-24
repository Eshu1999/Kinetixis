KinetixisMM website - how to put it online

Upload to any web host (Netlify, Cloudflare Pages, GitHub Pages, your hosting panel):
   index.html          the main site (one page with all sections)
   pages\*.html        the same legal and info pages as separate files (for Razorpay, Google and sharing links)
Keep the "pages" folder next to index.html.

Before uploading: fill the yellow placeholders (phone number, grievance officer), and set your payment link:
   open index.html, find  const CHECKOUT=""  and paste your Razorpay Payment Page link between the quotes.
(If you have the build folder: put the edited index.html in it as model-merger-site.html and run  python build_docs.py  - this also
 updates the pages folder.) See RAZORPAY_SETUP.txt for the full steps.
