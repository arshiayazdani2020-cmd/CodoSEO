#!/usr/bin/env python3
"""Controlled RAJ synthetic Persian site; no real target, no external URLs."""
import html
import json
import pathlib
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

binary = str(pathlib.Path(sys.argv[1]).resolve())
out = pathlib.Path(sys.argv[2]).resolve()
out.mkdir(parents=True, exist_ok=True)
paths = ["/", "/services", "/broken", "/metadata", "/blog", "/contact"]
title = "خدمات طراحی وب‌سایت و راهکارهای دیجیتال راژ"
description = "آزمایش فارسی با نیم‌فاصله، عدد ۱۲۳ و نویسه‌های ي ی ك ک & متن نمونه."
paragraph = "این صفحه آزمایشی برای بررسی کیفیت استخراج محتوای فارسی و راهکارهای دیجیتال طراحی شده است. "
state = {"fixed": False}
origin = ""

def page(path, name, body, meta=True):
    head = '<meta charset="utf-8">'
    if meta:
        head += f'<title>{html.escape(name)}</title><meta name="description" content="{html.escape(description)}">'
    head += f'<link rel="canonical" href="{origin}{path}">'
    return f'<!doctype html><html lang="fa" dir="rtl"><head>{head}</head><body>{body}</body></html>'

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlsplit(self.path).path
        fixed = state["fixed"]
        status, typ = 200, "text/html; charset=utf-8"
        if path == "/robots.txt":
            typ = "text/plain; charset=utf-8"
            body = "User-agent: *\nAllow: /\n\nUser-agent: GPTBot\nDisallow: /\n\n"
            if not fixed:
                body += "User-agent: OAI-SearchBot\nDisallow: /\n\n"
            body += f"Sitemap: {origin}/sitemap.xml\n"
        elif path == "/sitemap.xml":
            typ = "application/xml"
            body = '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' + "".join(f"<url><loc>{origin}{p}</loc></url>" for p in paths) + "</urlset>"
        elif path == "/":
            body = page(path, "خانه آزمایش راژ", "<h1>خانه آزمایش</h1><main>" + paragraph * 5 + "</main>" + "".join(f'<a href="{p}">صفحه {i}</a>' for i,p in enumerate(paths[1:])))
        elif path == "/services":
            body = page(path, title, "<h1>خدمات وب‌سایت</h1><main>" + paragraph * 15 + "</main><a href='/'>خانه</a>")
        elif path == "/broken" and not fixed:
            status, body = 404, "Not found"
        elif path == "/broken":
            body = page(path, "صفحه بازیابی شده", "<h1>بازیابی</h1><main>صفحه بازیابی شد.</main><a href='/'>خانه</a>")
        elif path == "/metadata":
            body = page(path, "عنوان اصلاح‌شده", "<h1>محتوا</h1><main>متن نمونه برای عنوان و توضیحات.</main><a href='/'>خانه</a>", fixed)
        elif path == "/blog":
            if not fixed:
                body = page(path, "وبلاگ آزمایشی", '<div id="app"></div><script src="/app.js"></script>')
            else:
                body = page(path, "وبلاگ آزمایشی", "<h1>وبلاگ</h1><main>" + paragraph * 6 + "</main><a href='/'>خانه</a>")
        elif path == "/contact":
            body = page(path, "تماس با ما", "<h1>تماس با ما</h1><main>راه ارتباطی آزمایشی.</main><a href='/'>خانه</a>")
        elif path == "/app.js":
            typ, body = "application/javascript", "document.getElementById('app').textContent='محتوای جاوااسکریپت';"
        else:
            status, typ, body = 404, "text/plain", "Not found"
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", typ)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def log_message(self, *args):
        pass

server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
origin = f"http://127.0.0.1:{server.server_port}"
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
results = []

def crawl(name, policy=None):
    file = out / f"{name}.json"
    cmd = [binary, "crawl", origin + "/", "--max-pages", "30", "--max-time", "120", "--rps", "2", "--format", "json", "-o", str(file)]
    cmd += ["--policy", str(policy)] if policy else ["--no-policy"]
    print("COMMAND", json.dumps(cmd), flush=True)
    subprocess.run(cmd, check=True, timeout=150)
    data = json.loads(file.read_text(encoding="utf-8"))
    if data["format_version"] != 1 or data["snapshot"]["stop"]["kind"] != "completed":
        raise RuntimeError(f"{name}: incomplete or unsupported audit")
    if data["snapshot"]["origin"].rstrip("/") != origin:
        raise RuntimeError(f"{name}: unexpected origin")
    return data

def pages(a):
    return {urlsplit(p["url"]).path: p for p in a["snapshot"]["pages"]}

def has(a, path, bit):
    return bool(pages(a)[path]["issues"] & (1 << bit))

def findings(a, kind):
    return [f for f in a["ai_access"]["findings"] if f["kind"] == kind]

def shell_paths(a):
    return {urlsplit(e["url"]).path for f in findings(a,"content_missing") for e in f["evidence"].get("content",[])}

def bot(a, kind, token):
    return any(e["token"].casefold() == token.casefold() for f in findings(a,kind) for e in f["evidence"].get("bots",[]))

def record(case, ok, evidence):
    row = {"case":case,"passed":bool(ok),"evidence":evidence}
    results.append(row)
    print("RAJ_CASE",json.dumps(row,ensure_ascii=False),flush=True)

def stable(a):
    return {p: (v["status"], v["fields"]["title"], v["fields"]["word_count"], v["issues"] & ~(1 << 40)) for p,v in pages(a).items()}

def policy_file(name, stance):
    p = out / name
    p.write_text('[policy]\nversion = 1\n\n[[policy.seo.exceptions]]\ncheck = "thin_content"\nscope = "/contact"\nnote = "Intentional short contact page"\n\n[policy.ai]\nbots = { GPTBot = "'+stance+'" }\n', encoding="utf-8")
    return p

try:
    print("VERSION", subprocess.check_output([binary,"--version"],text=True).strip(),flush=True)
    baseline = crawl("baseline")
    repeat = crawl("baseline-repeat")
    state["fixed"] = True
    fixed = crawl("fixed")
    fixed_repeat = crawl("fixed-repeat")
    for label,a in [("baseline",baseline),("repeat",repeat),("fixed",fixed),("fixed-repeat",fixed_repeat)]:
        missing = set(paths) - set(pages(a))
        if missing:
            raise RuntimeError(f"{label}: required pages missing: {missing}")
    allowed = crawl("policy-allow-training",policy_file("allow.toml","allow"))
    blocked = crawl("policy-block-training",policy_file("block.toml","block"))
    for label,a in [("allow",allowed),("block",blocked)]:
        if set(paths) - set(pages(a)):
            raise RuntimeError(f"{label}: required pages missing")
    for a in [baseline,repeat,fixed,fixed_repeat,allowed,blocked]:
        if a["ai_access"].get("report") is None:
            raise RuntimeError("missing AI report")
    f = pages(baseline)["/services"]["fields"]
    record("FA-01",pages(baseline)["/services"]["status"]==200 and f["title"]==title and f["meta_description"]==description and not any(has(baseline,"/services",b) for b in [12,17,21]),{"title":f["title"],"description":f["meta_description"],"words":f["word_count"],"h1":f["h1"]})
    record("FA-02",pages(baseline)["/broken"]["status"]==404 and has(baseline,"/broken",0) and has(baseline,"/",27) and pages(fixed)["/broken"]["status"]==200 and not has(fixed,"/broken",0) and not has(fixed,"/",27),{"before":pages(baseline)["/broken"]["status"],"after":pages(fixed)["/broken"]["status"],"source_link_before":has(baseline,"/",27),"source_link_after":has(fixed,"/",27)})
    record("FA-03",has(baseline,"/metadata",12) and has(baseline,"/metadata",17) and not has(fixed,"/metadata",12) and not has(fixed,"/metadata",17),{"before":pages(baseline)["/metadata"]["fields"]["title"],"after":pages(fixed)["/metadata"]["fields"]["title"]})
    record("FA-04","/blog" in shell_paths(baseline) and "/blog" not in shell_paths(fixed),{"before":sorted(shell_paths(baseline)),"after":sorted(shell_paths(fixed))})
    record("FA-05",bot(baseline,"bots_blocked","OAI-SearchBot") and not bot(fixed,"bots_blocked","OAI-SearchBot"),{"before":bot(baseline,"bots_blocked","OAI-SearchBot"),"after":bot(fixed,"bots_blocked","OAI-SearchBot")})
    excluded = dict(blocked["report"].get("excluded",{}).get("counts",[]))
    record("FA-06",has(fixed,"/contact",24) and "/contact" not in shell_paths(fixed) and has(blocked,"/contact",24) and excluded.get("thin_content",0)==1,{"raw_thin":has(blocked,"/contact",24),"shell":"/contact" in shell_paths(fixed),"excluded_thin":excluded.get("thin_content",0)})
    record("FA-07",bot(allowed,"bots_blocked","GPTBot") and not bot(blocked,"bots_blocked","GPTBot") and not bot(blocked,"bots_not_blocked","GPTBot"),{"allow_policy_blocked_finding":bot(allowed,"bots_blocked","GPTBot"),"block_policy_blocked_finding":bot(blocked,"bots_blocked","GPTBot"),"block_policy_not_blocked_finding":bot(blocked,"bots_not_blocked","GPTBot")})
    cmd = [binary,"diff",str(out/"baseline.json"),str(out/"fixed.json"),"--format","json"]
    print("COMMAND",json.dumps(cmd),flush=True)
    diff = json.loads(subprocess.check_output(cmd,timeout=30,text=True))
    (out/"diff.json").write_text(json.dumps(diff,ensure_ascii=False,indent=2),encoding="utf-8")
    status_change = any(d["kind"]=="status_changed" and urlsplit(d.get("url") or "").path=="/broken" and d["before"]=="404" and d["after"]=="200" for d in diff)
    robots_change = any(d["kind"]=="robots_txt_changed" for d in diff)
    # CLI diff does not guarantee metadata restoration or GEO incident resolution; raw snapshots above cover those.
    record("FA-08",status_change and robots_change and stable(baseline)==stable(repeat) and stable(fixed)==stable(fixed_repeat) and pages(baseline)["/services"]["fields"]["title"]==pages(fixed)["/services"]["fields"]["title"],{"status_change":status_change,"robots_change":robots_change,"baseline_repeat":stable(baseline)==stable(repeat),"fixed_repeat":stable(fixed)==stable(fixed_repeat),"diff_kinds":[d["kind"] for d in diff]})
    (out/"cases.json").write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding="utf-8")
    print("RAJ_SUMMARY",json.dumps({"passed":sum(r["passed"] for r in results),"total":len(results),"durations_ms":{k:a["duration_ms"] for k,a in [("baseline",baseline),("repeat",repeat),("fixed",fixed),("fixed_repeat",fixed_repeat),("allow",allowed),("block",blocked)]}},ensure_ascii=False),flush=True)
    if not all(r["passed"] for r in results):
        sys.exit(1)
finally:
    server.shutdown()
    server.server_close()
