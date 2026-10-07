# UPI SHIELD frontend

Run the API from `backend` with `npm start`, then start the frontend with `npm run dev` from this directory. Vite proxies `/api` requests to `http://localhost:8000` by default.

The scanner uses the backend unless `VITE_DEMO_MODE=true` is set. To use a separately hosted API, set `VITE_API_BASE_URL` to its base URL; the client adds `/api` when it is not already present. If the API cannot be reached, scan requests fall back to clearly marked demo results.

URL scans use local keyword and URL-pattern matching on the backend. They do not call paid APIs, query external reputation services, open submitted websites, or follow redirects. Checks include suspicious payment/login/verification keywords, brand impersonation, raw IP hosts, excessive subdomains, punycode, non-standard ports, insecure HTTP, and credential-like query parameter names. Query parameter values are redacted from saved scan results. These heuristic checks cannot establish that a payment URL is safe; verify the payee through your bank or UPI app.

Camera access requires HTTPS or localhost. PDF export opens the browser print dialog; the app does not generate a PDF file itself.
