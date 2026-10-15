"""
check_recon.py -- automatic PASS / FAIL check for recon.py.

ONLY for the local PRACTICE site, never for the real target.

How to run it (3 steps):
  1. Terminal 1:  go into the practice_site folder and start the server
                     python test_server.py
     (leave this window open)
  2. Terminal 2:  go into the recon folder (where recon.py is) and run
                     python check_recon.py
  3. Read the PASS / FAIL lines. Every line should say PASS.
     It takes about 20 seconds because recon.py waits 1 second per page.
"""

from recon import run

PRACTICE = "http://localhost:8000/"

results = []


def check(description, passed):
    """Record one check and print PASS or FAIL for it."""
    results.append(passed)
    print(("PASS  " if passed else "FAIL  ") + description)


def has_param(params, url, method, names):
    """True if the params list has an entry with this url and method containing at least these names."""
    for p in params:
        if p["url"] == url and p["method"] == method and set(names) <= set(p["params"]):
            return True
    return False


print("Running recon against the practice site...\n")
out = run(PRACTICE)
endpoints = out["endpoints"]
params = out["params"]
all_text = " ".join(endpoints) + " " + str(params)   # used for "does this text appear anywhere?"

print("\n--- Results ---")

# 1. Output shape (the contract the other modules depend on)
check("output has the 3 keys: tech_stack, endpoints, params",
      {"tech_stack", "endpoints", "params"} <= set(out))

# 2. Fingerprinting
check("fingerprint found the server header",
      "server" in out["tech_stack"])
check("fingerprint found the generator meta tag (PracticeGen 1.0)",
      out["tech_stack"].get("cms_or_generator") == "PracticeGen 1.0")

# 3. Crawling: pages that SHOULD be found
check("home page is an endpoint",
      "http://localhost:8000/" in endpoints)
check("login page is an endpoint",
      "http://localhost:8000/login" in endpoints)
check("contact page (relative link 'contact/') is an endpoint",
      "http://localhost:8000/contact/" in endpoints)
check("page at depth 2 (level1/level2/) is an endpoint",
      "http://localhost:8000/level1/level2/" in endpoints)

# 4. Crawling: things that should NOT be found
check("depth-3 page was NOT crawled (past max depth)",
      "level3" not in all_text)
check("404 page is NOT an endpoint",
      "missing-page" not in all_text)
check("mailto:, javascript: and external links were NOT followed",
      "mailto" not in all_text and "javascript" not in all_text and "example.com" not in all_text)
check("off-site redirect (127.0.0.1) was NOT followed",
      "127.0.0.1" not in all_text)
check("redirect /old-login was recorded as its final page /login (not /old-login)",
      "http://localhost:8000/old-login" not in endpoints)
check("no duplicate endpoints",
      len(endpoints) == len(set(endpoints)))

# 5. Forms and params
check("login form: POST /session with username + password (action resolved)",
      has_param(params, "http://localhost:8000/session", "POST", ["username", "password"]))
check("contact form: relative action '/login' resolved to site root",
      has_param(params, "http://localhost:8000/login", "POST", ["email", "subject"]))
check("textarea field 'message' was captured",
      any("message" in p["params"] for p in params))
check("search form: GET /search with q",
      has_param(params, "http://localhost:8000/search", "GET", ["q"]))
check("query-string params: GET /search with q and lang",
      has_param(params, "http://localhost:8000/search", "GET", ["q", "lang"]))
check("comment form on depth-2 page: relative action 'comments' resolved",
      has_param(params, "http://localhost:8000/level1/level2/comments", "POST",
                ["comment_author", "comment_body"]))
check("form with no named fields was skipped",
      not any(p["url"].endswith("/nothing") for p in params))
check("form on depth-3 page (/secret) was NOT captured",
      "secret" not in all_text)
check("no duplicate param entries",
      len(params) == len({(p["url"], p["method"], tuple(p["params"])) for p in params}))

passed = sum(results)
total = len(results)
print(f"\n{passed} of {total} checks passed.")
if passed == total:
    print("ALL GOOD. recon.py behaves as expected on the practice site.")
else:
    print("SOME CHECKS FAILED. Read the FAIL lines above and check recon.py.")
