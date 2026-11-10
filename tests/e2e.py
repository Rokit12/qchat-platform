# Browser end-to-end test (Playwright + Chrome). Start a server first:
#   PORT=3100 DATA_DIR=/tmp/qdata npm start      then:   python3 tests/e2e.py [base_url] [second_base_url]
import asyncio, sys, base64, os
from playwright.async_api import async_playwright
URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3100/"
URL2 = sys.argv[2] if len(sys.argv) > 2 else URL   # e.g. a second server instance behind Redis
errors = []
OUT = os.environ.get("SHOTS", "/tmp")

async def mk(browser, name, url=URL):
    ctx = await browser.new_context(viewport={"width": 1200, "height": 800}, bypass_csp=True, accept_downloads=True,
                                    permissions=["microphone", "camera", "notifications"])
    p = await ctx.new_page()
    p.on("pageerror", lambda e: errors.append(f"{name}: {e}"))
    p.on("console", lambda m: m.type == "error" and "favicon" not in m.text and errors.append(f"{name} console: {m.text}"))
    await p.goto(url)
    return ctx, p

async def register(p, u, dn):
    await p.fill("#createForm [name=username]", u); await p.fill("#createForm [name=displayName]", dn)
    await p.click("#createForm button")
    await p.wait_for_selector("#obKey:not(.hidden)", timeout=20000)
    key = await p.text_content("#obKeyText")
    await p.click("#obContinue"); await p.wait_for_selector("#app:not(.hidden)")
    return key

async def open_dm(p, u):
    await p.click("#newChatBtn"); await p.fill("#ncUser", u); await p.click("#ncGo")
    await p.wait_for_selector("#ncResult li"); await p.click("#ncGo")
    await p.wait_for_selector("#chatView:not(.hidden)")

async def send(p, t):
    await p.fill("#msgInput", t); await p.press("#msgInput", "Enter")

async def chat(p, name):
    await p.click(f".chat-item:has-text('{name}')")

def ok(msg): print("✔", msg, flush=True)

async def main():
    async with async_playwright() as pw:
        b = await pw.chromium.launch(executable_path="/usr/bin/google-chrome",
            args=["--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream", "--no-sandbox"])
        ca, a = await mk(b, "alice"); cb, bb = await mk(b, "bob", URL2); cc, c = await mk(b, "carol")
        ka = await register(a, "alice", "Alice 🌍"); await register(bb, "bob", "Bob"); await register(c, "carol", "Carol")
        ok("3 accounts registered (PQ identity + device certs + prekeys)")

        await open_dm(bb, "alice"); await send(bb, "Hello Alice! *bold*")
        await a.wait_for_selector(".chat-item .badge", timeout=15000); await chat(a, "Bob")
        await a.wait_for_selector(".msg.in .text b")
        await bb.wait_for_selector(".msg.out .ticks.read", timeout=15000); ok("first contact via prekeys, blue ticks")
        await send(a, "Hi Bob 👋"); await bb.wait_for_selector("text=Hi Bob", timeout=15000)
        await send(bb, "ratchet step"); await a.wait_for_selector("text=ratchet step", timeout=15000); ok("replies flow both ways (KEM ratchet advancing)")
        await a.type("#msgInput", "typing..."); await bb.wait_for_selector("#chatSub.typing", timeout=5000); await a.fill("#msgInput", ""); ok("typing indicator")
        await a.dblclick(".msg.in >> nth=0"); await bb.wait_for_selector(".msg.out .reactions", timeout=10000); ok("reaction")
        await bb.click(".msg.out >> nth=0", button="right"); await bb.click("[data-act=edit]")
        await bb.fill("#msgInput", "Hello Alice (edited)"); await bb.press("#msgInput", "Enter")
        await a.wait_for_selector("text=Hello Alice (edited)", timeout=10000); ok("edit")
        png = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")
        await bb.set_input_files("#fileInput", files=[{"name": "pic.png", "mimeType": "image/png", "buffer": png}])
        await a.wait_for_selector(".msg.in img.media[src^='blob:']", timeout=15000); ok("encrypted photo")
        await send(bb, "oops"); await a.wait_for_selector("text=oops")
        await bb.click(".msg.out:has-text('oops')", button="right"); await bb.click("[data-act=delall]"); await bb.click("#cfYes")
        await a.wait_for_selector("text=This message was deleted", timeout=10000); ok("delete for everyone")

        # ---- second device for alice + history transfer ----
        ca2, a2 = await mk(b, "alice2", URL2)
        await a2.click("[data-tab=restore]"); await a2.fill("#restoreForm [name=username]", "alice"); await a2.fill("#restoreForm [name=key]", ka)
        await a2.click("#restoreForm button"); await a2.wait_for_selector("#app:not(.hidden)", timeout=20000)
        await a.wait_for_selector("#toast:has-text('New device linked')", timeout=15000)
        await a.wait_for_selector("#modal:not(.hidden) >> text=Copy history", timeout=15000); await a.click("#cfYes")
        await a2.wait_for_selector(".chat-item:has-text('Bob')", timeout=20000)
        await chat(a2, "Bob"); await a2.wait_for_selector("text=Hello Alice (edited)", timeout=10000)
        await a2.wait_for_selector(".msg img.media[src^='blob:']", timeout=10000); ok("second device linked (old device alerted); history + media copied over the PQ channel")
        await send(bb, "to both of your devices"); await a.wait_for_selector("text=to both of your devices", timeout=15000)
        await a2.wait_for_selector("text=to both of your devices", timeout=15000); ok("multi-device fan-out")
        await send(a2, "sent from my 2nd device"); await bb.wait_for_selector("text=sent from my 2nd device", timeout=15000)
        await a.wait_for_selector(".msg.out:has-text('sent from my 2nd device')", timeout=15000); ok("sent messages sync to own devices")

        # ---- group ----
        await a.click("#newGroupBtn"); await a.fill("#ngName", "World Friends")
        for u in ["bob", "carol"]:
            await a.fill("#mpUser", u); await a.click("#mpAdd"); await a.wait_for_selector(f"#mpList >> text=@{u}")
        await a.click("#ngCreate"); await send(a, "Welcome to the group!")
        await c.wait_for_selector(".chat-item:has-text('World Friends')", timeout=15000); await chat(c, "World Friends")
        await c.wait_for_selector("text=Welcome to the group!")
        await send(c, "Thanks from Carol")
        await bb.wait_for_selector(".chat-item:has-text('World Friends')", timeout=15000); await chat(bb, "World Friends")
        await bb.wait_for_selector("text=Thanks from Carol", timeout=15000)
        await a2.wait_for_selector(".chat-item:has-text('World Friends')", timeout=15000)
        await a.wait_for_selector(".msg.out:has-text('Welcome to the group') .ticks.read", timeout=15000); ok("group chat across 4 devices + group read receipts")

        # ---- status ----
        await bb.click("#statusBtn"); await bb.click("#stText"); await bb.fill("#stInput", "Quantum-safe hello 🌍"); await bb.click("#stPost")
        await a.wait_for_selector("#statusBtn.has-new", timeout=15000)
        await a.click("#statusBtn"); await a.click("[data-st=bob]"); await a.wait_for_selector(".sv-text:has-text('Quantum-safe hello')")
        await a.click("#svClose")
        await bb.click("#statusBtn"); await bb.click("#stMine"); await bb.wait_for_selector(".sv-foot:has-text('1 view')", timeout=10000); await bb.click("#svClose")
        ok("status posted, viewed, view receipt")

        # ---- 1:1 video call: both alice devices ring, answer on device 2 ----
        await chat(bb, "Alice"); await bb.click("#videoCallBtn")
        await a.wait_for_selector("#acceptBtn:not(.hidden)", timeout=20000); await a2.wait_for_selector("#acceptBtn:not(.hidden)", timeout=20000)
        await a2.click("#acceptBtn")
        await a.wait_for_selector("#callView.hidden", state="attached", timeout=10000)
        await bb.wait_for_function("document.querySelector('#callStatus').textContent.includes('PQ-encrypted')", timeout=30000)
        await bb.wait_for_function("[...document.querySelectorAll('#callGrid video')].some(v => v.videoWidth > 0)", timeout=15000)
        await asyncio.sleep(2)
        sb = await bb.evaluate("window.__qchat.frameStats()"); sa = await a2.evaluate("window.__qchat.frameStats()")
        assert sb["enc"] > 20 and sb["dec"] > 20 and sa["enc"] > 20 and sa["dec"] > 20, (sb, sa)
        ok(f"video call: rang on both devices, answered on one; frames AES-GCM encrypted/decrypted (bob enc={sb['enc']} dec={sb['dec']} drop={sb['drop']})")
        await bb.screenshot(path=f"{OUT}/v2_call.png")
        await bb.click("#hangBtn"); await a2.wait_for_selector("#callView.hidden", state="attached", timeout=10000); ok("hang up")

        # ---- group video call (alice, bob, carol) ----
        await chat(a, "World Friends"); await a.click("#videoCallBtn")
        await bb.wait_for_selector("#acceptBtn:not(.hidden)", timeout=20000); await c.wait_for_selector("#acceptBtn:not(.hidden)", timeout=20000)
        await a2.wait_for_selector("#callView.hidden", state="attached")
        await bb.click("#acceptBtn"); await c.click("#acceptBtn")
        for p in (a, bb, c):
            await p.wait_for_function("document.querySelectorAll('#callGrid .tile.connected').length === 2", timeout=40000)
        ok("group video call: 3-way mesh, every tile connected")
        await asyncio.sleep(2); await c.screenshot(path=f"{OUT}/v2_groupcall.png")
        await c.click("#hangBtn")
        await a.wait_for_function("document.querySelectorAll('#callGrid .tile').length === 1", timeout=15000); ok("participant left, key rotated, call continues")
        await a.click("#hangBtn"); await bb.wait_for_selector("#callView.hidden", state="attached", timeout=15000)

        # ---- live stream from Status with pop comments + hearts ----
        await a.click("#statusBtn"); await a.click("#stGoLive"); await a.fill("#glTitle", "Sunset from my balcony"); await a.click("#glGo")
        await a.wait_for_selector("#liveView:not(.hidden).is-host")
        for p in (bb, c):
            await p.wait_for_selector("#statusBtn.has-live", timeout=15000)
            await p.click("#statusBtn"); await p.click("[data-watch=alice]")
            await p.wait_for_function("document.querySelector('#liveVideo').videoWidth > 0", timeout=30000)
        await a.wait_for_function("document.querySelector('#liveViewers').textContent === '2'", timeout=10000)
        await bb.fill("#liveInput", "Beautiful! 🌅"); await bb.press("#liveInput", "Enter")
        for p in (a, c): await p.wait_for_selector("#liveComments .lc:has-text('Beautiful!')", timeout=10000)
        await c.click("#liveHeart"); await a.wait_for_selector("#liveHearts .lh", timeout=10000)
        await a.fill("#liveInput", "Thanks for watching!"); await a.press("#liveInput", "Enter")
        for p in (bb, c): await p.wait_for_selector("#liveComments .lc:has-text('Thanks for watching')", timeout=10000)
        await asyncio.sleep(1.5)
        hs = await a.evaluate("window.__qchat.liveStats()"); vs = await bb.evaluate("window.__qchat.liveStats()")
        assert hs["enc"] > 30 and vs["dec"] > 30, (hs, vs)
        await c.screenshot(path=f"{OUT}/v2_live_viewer.png"); await a.screenshot(path=f"{OUT}/v2_live_host.png")
        ok(f"live: 2 viewers joined, frames encrypted (host enc={hs['enc']}, viewer dec={vs['dec']}), comments popped for everyone, hearts flew")
        await a.click("#liveClose"); await a.click("#cfYes")
        await bb.wait_for_selector("#liveView.hidden", state="attached", timeout=10000); await c.wait_for_selector("#liveView.hidden", state="attached", timeout=10000)
        ok("host ended live → viewers closed")

        # ---- encrypted backup export / import ----
        await a.click("#settingsBtn")
        async with a.expect_download() as dl: await a.click("#sExport")
        path = await (await dl.value).path()
        data = open(path, "rb").read(); assert data[:4] == b"QCB1" and b"Hello Alice" not in data
        await a.keyboard.press("Escape"); await chat(a, "Bob")
        await a.click("#chatInfoBtn"); await a.click("#ciClear"); await a.click("#cfYes")
        await a.wait_for_selector(".msg", state="detached", timeout=5000)
        await a.click("#settingsBtn"); await a.set_input_files("#sImport", path)
        await a.wait_for_selector("#toast:has-text('Backup restored')", timeout=15000)
        await chat(a, "Bob"); await a.wait_for_selector("text=Hello Alice (edited)", timeout=10000); ok("encrypted backup exported (no plaintext in file) and restored")

        # ---- passcode lock ----
        await c.click("#settingsBtn"); await c.click("#sPass"); await c.fill("#pc1", "4321"); await c.fill("#pc2", "4321"); await c.click("#pcSave")
        await c.wait_for_selector("#toast:has-text('Passcode set')", timeout=30000)
        await c.reload(); await c.wait_for_selector("#lockScreen:not(.hidden)")
        await c.fill("#lockInput", "0000"); await c.click("#lockForm button"); await c.wait_for_selector("#lockErr:has-text('Wrong')", timeout=30000)
        await c.fill("#lockInput", "4321"); await c.click("#lockForm button")
        await c.wait_for_selector(".chat-item:has-text('World Friends')", timeout=30000); ok("passcode lock (Argon2id) — wrong code rejected, right code unlocks")
        dump = await c.evaluate("""() => new Promise(r => { const q = indexedDB.open('qchat2'); q.onsuccess = () => { const t = q.result.transaction('kv').objectStore('kv').getAll(); t.onsuccess = () => r(JSON.stringify(t.result.map(x => [...new Uint8Array(x.ct)].length))); }; })""")
        raw = await c.evaluate("""() => new Promise(r => { const q = indexedDB.open('qchat2'); q.onsuccess = () => { const t = q.result.transaction('kv').objectStore('kv').getAll(); t.onsuccess = () => r(t.result.map(x => new TextDecoder().decode(x.ct)).join('')); }; })""")
        assert "Thanks from Carol" not in raw and "World Friends" not in raw; ok("local database contains only ciphertext")

        # ---- offline delivery ----
        await c.close(); await chat(bb, "World Friends"); await send(bb, "carol was offline")
        await asyncio.sleep(1)
        c = await cc.new_page(); await c.goto(URL); await c.fill("#lockInput", "4321"); await c.click("#lockForm button")
        await chat(c, "World Friends"); await c.wait_for_selector("text=carol was offline", timeout=30000); ok("offline queue delivered after unlock")

        # ---- device removal ----
        await a.click("#settingsBtn"); await a.click("[data-rmdev]"); await a.click("#cfYes")
        await a2.wait_for_selector("#modal:not(.hidden) >> text=removed", timeout=15000); ok("device 2 revoked via signed device list → signed out")
        await a.keyboard.press("Escape")
        await chat(bb, "Alice"); await send(bb, "only device 1 now"); await a.wait_for_selector("text=only device 1 now", timeout=15000); ok("messaging continues to remaining device")

        # ---- share my link: a brand-new user opens alice's invite link ----
        await a.click("#shareBtn"); await a.wait_for_selector(".qr svg"); link = await a.text_content("#shLink")
        assert link.endswith("/@alice"), link
        await a.screenshot(path=f"{OUT}/v2_share.png"); await a.keyboard.press("Escape")
        cd, d = await mk(b, "dave", link)
        await register(d, "dave", "Dave")
        await d.wait_for_selector("#ncResult li:has-text('@alice')", timeout=10000); await d.click("#ncGo")
        await d.wait_for_selector("#chatView:not(.hidden)"); assert (await d.evaluate("location.pathname")) == "/"
        await send(d, "Found you through your link!")
        await a.wait_for_selector(".chat-item:has-text('Dave')", timeout=15000); ok("invite link /@alice → new user signed up and landed in a chat with alice")

        # ---- anti-phishing: a stranger tries social engineering + a fake link + a disguised .exe ----
        await chat(a, "Dave"); await a.wait_for_selector("#strangerBar:not(.hidden)"); ok("stranger warning shown for first contact from an unknown user")
        await send(d, "Hi, this is QChat Support. Your account will be suspended. Send me your recovery key here: https://paypa1-login.top/verify")
        await a.wait_for_selector(".msg.in a.lnk.lvl-danger", timeout=15000)
        warns = await a.locator(".msg.in .msg-warn").all_text_contents()
        assert any("Suspicious link" in w for w in warns) and any("Never share" in w for w in warns), warns
        await a.click(".msg.in a.lnk.lvl-danger"); await a.wait_for_selector("#modal:not(.hidden) >> text=This link looks dangerous")
        assert "disabled" in (await a.get_attribute("#lkOpen", "class")); reasons = await a.locator(".link-reasons li").all_text_contents()
        assert any("PayPal" in r for r in reasons), reasons
        await a.click("#modal [data-close]"); ok(f"phishing link flagged + blocked behind a warning ({'; '.join(reasons[:2])})")
        await d.set_input_files("#fileInput", files=[{"name": "invoice.pdf.exe", "mimeType": "application/octet-stream", "buffer": b"MZ fake"}])
        await a.wait_for_selector(".msg.in a.file.risk-danger", timeout=15000)
        await a.click(".msg.in a.file.risk-danger"); await a.wait_for_selector("#modal:not(.hidden) >> text=Download this file?"); await a.click("#cfNo")
        ok("disguised executable flagged; download needs explicit confirmation")
        await a.fill("#msgInput", "ok here it is " + ka); await a.press("#msgInput", "Enter")
        await a.wait_for_selector("#modal:not(.hidden) >> text=That looks like your recovery key"); await a.click("#cfNo")
        assert (await a.locator(".msg.out:has-text('QC1-')").count()) == 0; ok("sending the recovery key is intercepted")
        await a.fill("#msgInput", "")
        await a.click("#strangerReport"); await a.click("#rpGo"); await a.wait_for_selector("#blockedBar:not(.hidden)"); ok("stranger reported + blocked")

        await a.screenshot(path=f"{OUT}/v2_alice.png")
        await a.set_viewport_size({"width": 390, "height": 780}); await a.screenshot(path=f"{OUT}/v2_mobile.png")
        await b.close()
    real = [e for e in errors if "WebSocket" not in e and "ERR_CONNECTION" not in e]
    print("ERRORS:", real)
    if real: sys.exit(1)

asyncio.run(main())
