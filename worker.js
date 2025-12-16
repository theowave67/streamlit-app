export default {
    async fetch(request, env, ctx) {
        // 1. Parse URLs
        const urlsRaw = env.URLS;
        if (!urlsRaw) {
            return new Response("Error: Missing 'URLS' environment variable.", { status: 400 });
        }

        let urls = [];
        try {
            const parsed = JSON.parse(urlsRaw);
            if (Array.isArray(parsed)) {
                urls = parsed;
            } else {
                throw new Error("Not a JSON array");
            }
        } catch (e) {
            urls = urlsRaw.split(/[\n,]+/).map(u => u.trim()).filter(u => u.length > 0);
        }

        if (urls.length === 0) {
            return new Response("Error: 'URLS' environment variable is empty.", { status: 400 });
        }

        // 2. Base Headers
        const baseHeaders = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "accept-language": "zh-CN,zh;q=0.7",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "priority": "u=0, i",
            "sec-ch-ua": "\"Brave\";v=\"143\", \"Chromium\";v=\"143\", \"Not A(Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "none",
            "sec-fetch-user": "?1",
            "sec-gpc": "1",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
        };

        // 3. Helper: Manual Fetch with Cookie Persistence
        async function fetchWithCookies(initialUrl) {
            let currentUrl = initialUrl;
            let referer = null; // Store previous URL for Referer header
            const cookieJar = new Map();
            const maxRedirects = 25;
            const history = [];

            for (let i = 0; i < maxRedirects; i++) {
                // Construct headers
                const headers = new Headers(baseHeaders);
                if (cookieJar.size > 0) {
                    const cookieString = Array.from(cookieJar.entries()).map(([k, v]) => `${k}=${v}`).join('; ');
                    headers.set('Cookie', cookieString);
                }
                if (referer) {
                    headers.set('Referer', referer);
                }

                try {
                    const response = await fetch(currentUrl, {
                        method: 'GET',
                        headers: headers,
                        redirect: 'manual'
                    });

                    history.push({ status: response.status, url: currentUrl });

                    // Extract and update cookies
                    let setCookies = [];
                    if (typeof response.headers.getSetCookie === 'function') {
                        setCookies = response.headers.getSetCookie();
                    } else {
                        const raw = response.headers.get('set-cookie');
                        if (raw) setCookies = [raw];
                    }

                    setCookies.forEach(str => {
                        const parts = str.split(';');
                        if (parts.length > 0) {
                            const pair = parts[0].trim();
                            const eqIdx = pair.indexOf('=');
                            if (eqIdx > 0) {
                                const key = pair.substring(0, eqIdx).trim();
                                const val = pair.substring(eqIdx + 1).trim();

                                // Check for deletion markers
                                let isDeletion = false;
                                for (let j = 1; j < parts.length; j++) {
                                    const attr = parts[j].trim().toLowerCase();
                                    if (attr === 'max-age=0' || attr === 'expires=thu, 01 jan 1970 00:00:00 gmt') {
                                        isDeletion = true;
                                        break;
                                    }
                                }

                                if (isDeletion) {
                                    cookieJar.delete(key);
                                } else {
                                    cookieJar.set(key, val);
                                }
                            }
                        }
                    });

                    // Handle Redirects
                    if (response.status >= 300 && response.status < 400) {
                        const location = response.headers.get('location');
                        if (location) {
                            referer = currentUrl; // Set referer for next request
                            currentUrl = new URL(location, currentUrl).toString();
                            continue;
                        }
                    }

                    if (response.status === 200) {
                        await response.text();
                    }

                    return {
                        url: initialUrl,
                        status: response.status,
                        ok: response.status === 200,
                        finalUrl: currentUrl,
                        history: history,
                        cookies: Object.fromEntries(cookieJar)
                    };

                } catch (err) {
                    return { url: initialUrl, error: err.message, ok: false };
                }
            }

            return {
                url: initialUrl,
                error: "Too many redirects",
                ok: false,
                history: history
            };
        };

        // 4. Execute requests
        const results = await Promise.all(urls.map(url => fetchWithCookies(url)));

        return new Response(JSON.stringify(results, null, 2), {
            headers: { "content-type": "application/json;charset=UTF-8" }
        });
    }
};