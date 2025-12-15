import express from "express";
import path from "path";
import fs from "fs";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import cors from "cors";
import dotenv from "dotenv";

/**
 * @interface ServerSideFingerprint
 * Signals collected server-side (Safari 17+ resistant)
 */
interface ServerSideFingerprint {
    // HTTP Headers
    userAgent: string;
    acceptLanguage: string;
    acceptEncoding: string;
    accept: string;

    // Connection info
    ipAddress: string;
    xForwardedFor: string | null;
    xRealIp: string | null;

    // TLS fingerprinting placeholders (requires reverse proxy integration)
    tlsVersion: string | null;
    tlsCipherSuite: string | null;
    ja3Hash: string | null;  // JA3 fingerprint (set by reverse proxy)
    ja4Hash: string | null;  // JA4 fingerprint (set by reverse proxy)

    // Request characteristics
    connectionType: string | null;
    dnt: string | null;
    secFetchDest: string | null;
    secFetchMode: string | null;
    secFetchSite: string | null;
    secChUa: string | null;  // Client hints
    secChUaPlatform: string | null;
    secChUaMobile: string | null;

    // Timing
    timestamp: number;
}

/**
 * @interface ClientSideFingerprint
 * Signals collected client-side and sent to server
 */
interface ClientSideFingerprint {
    // Screen (Safari 17+ returns document size, but we collect anyway for fallback)
    screenWidth: number;
    screenHeight: number;
    screenAvailWidth: number;
    screenAvailHeight: number;
    screenColorDepth: number;
    devicePixelRatio: number;

    // Window (useful as fallback)
    innerWidth: number;
    innerHeight: number;
    outerWidth: number;
    outerHeight: number;

    // Navigator properties
    hardwareConcurrency: number;
    deviceMemory: number | null;
    maxTouchPoints: number;
    language: string;
    languages: string[];
    platform: string;
    vendor: string;
    cookieEnabled: boolean;
    doNotTrack: string | null;

    // Timezone
    timezone: string;
    timezoneOffset: number;

    // WebGL (Safari still exposes some of this)
    webglVendor: string | null;
    webglRenderer: string | null;

    // Canvas fingerprint hash
    canvasHash: string | null;

    // Audio fingerprint hash
    audioHash: string | null;

    // Font detection results
    fontsHash: string | null;

    // Feature detection
    webrtcEnabled: boolean;
    indexedDbEnabled: boolean;
    sessionStorageEnabled: boolean;
    localStorageEnabled: boolean;
}

/**
 * @interface CombinedFingerprint
 * Full fingerprint combining server and client signals
 */
interface CombinedFingerprint {
    uid: string;
    serverFingerprint: ServerSideFingerprint;
    clientFingerprint: ClientSideFingerprint | null;
    faviconIdentifier: number | null;
    combinedHash: string;
    timestamp: number;
}

/**
 * Stores fingerprint data
 */
const fingerprintStore: Map<string, CombinedFingerprint> = new Map();

/**
 * Extracts server-side fingerprint from request
 */
const extractServerFingerprint = (req: express.Request): ServerSideFingerprint => {
    // Get real IP address (behind proxy)
    const xForwardedFor = req.headers['x-forwarded-for'] as string || null;
    const xRealIp = req.headers['x-real-ip'] as string || null;
    const ipAddress = xRealIp ||
        (xForwardedFor ? xForwardedFor.split(',')[0].trim() : null) ||
        req.ip ||
        req.socket?.remoteAddress ||
        'unknown';

    return {
        // HTTP Headers
        userAgent: req.headers['user-agent'] || '',
        acceptLanguage: req.headers['accept-language'] || '',
        acceptEncoding: req.headers['accept-encoding'] || '',
        accept: req.headers['accept'] || '',

        // Connection info
        ipAddress,
        xForwardedFor,
        xRealIp,

        // TLS fingerprinting (requires reverse proxy headers like X-JA3-Fingerprint)
        tlsVersion: req.headers['x-tls-version'] as string || null,
        tlsCipherSuite: req.headers['x-tls-cipher'] as string || null,
        ja3Hash: req.headers['x-ja3-fingerprint'] as string || null,
        ja4Hash: req.headers['x-ja4-fingerprint'] as string || null,

        // Request characteristics
        connectionType: req.headers['connection'] || null,
        dnt: req.headers['dnt'] as string || null,
        secFetchDest: req.headers['sec-fetch-dest'] as string || null,
        secFetchMode: req.headers['sec-fetch-mode'] as string || null,
        secFetchSite: req.headers['sec-fetch-site'] as string || null,
        secChUa: req.headers['sec-ch-ua'] as string || null,
        secChUaPlatform: req.headers['sec-ch-ua-platform'] as string || null,
        secChUaMobile: req.headers['sec-ch-ua-mobile'] as string || null,

        timestamp: Date.now()
    };
};

/**
 * Creates a hash from fingerprint data for identification
 */
const hashFingerprint = (data: object): string => {
    return crypto.createHash('sha256')
        .update(JSON.stringify(data))
        .digest('hex')
        .slice(0, 16);
};

/**
 * Creates UUID in the specified pattern's
 * form using charset
 * @param pattern 
 * @param charset 
 */
const generateUUID = (
    pattern: string = "xxxx-xxxx-xxxx-xxxx-xxxx", 
    charset: string = "abcdefghijklmnopqrstuvwxyz0123456789"): string =>
	pattern.replace(/[x]/g, () => charset[Math.floor(Math.random() * charset.length)]);

/**
 * Creates HEX-hash from number 
 * @param value
 */
const hashNumber = (value: number): string => crypto.createHash("MD5")
    .update(value.toString())
    .digest("hex").slice(-12).split(/(?=(?:..)*$)/)
    .join(' ').toUpperCase();

/**
 * Creates string-array with length "count"
 * from value "base"
 * @param base 
 * @param count 
 */
const createRoutes = (base: string, count: number): Array<string> => {
    const array = [];
    for (let i=0; i<count; i++)
        array.push(crypto.createHash("MD5")
            .update(`${base}${i.toString()}`).digest("base64")
            .replace(/(\=|\+|\/)/g, '0').substring(0, 22));
    return array;
}

/**
 * @class Storage
 * For writing and reading
 * persistent JSON on file-system
 */
class Storage {
    private _path: string = path.join(path.resolve(), "data.json");
    private _content: object = {};
    private _contentProxy: object;
    constructor() {
        if (!this.existsPersistent())
            this.createPersistent();
        this.read();
    }
    public get content(): any {
        return this._contentProxy;
    }
    public set content(data: any) {
        this._content = data;
        const _this = this;
        const proxy = {
            get(target: any, key: any) {
                if (typeof target[key] === 'object' && target[key] !== null) 
                    return new Proxy(target[key], proxy)
                else return target[key];
            },
            set (target: any, key: any, value: any): any {
                target[key] = value;
                _this.write(_this.content);
                return true;
            }
        }
        this._contentProxy = new Proxy(this._content, proxy);
        _this.write(_this.content);
    }
    private read(): Storage {
        return this.content = JSON.parse(fs.readFileSync(this._path).toString() || "{}"), this;
    }
    private write(content: object): Storage {
        fs.writeFileSync(this._path, JSON.stringify(content, null, '\t'));
        return this;
    }
    private createPersistent() {
        this.write({});
    }
    private existsPersistent() {
        return fs.existsSync(this._path);
    }
}
const STORAGE: any = new Storage().content;

/**
 * @class FingerprintStorage
 * Persistent storage for fingerprint data (Safari 17+ compatible)
 */
class FingerprintStorage {
    private _path: string = path.join(path.resolve(), "fingerprints.json");
    private _data: Map<string, CombinedFingerprint> = new Map();

    constructor() {
        this.load();
    }

    private load(): void {
        try {
            if (fs.existsSync(this._path)) {
                const raw = JSON.parse(fs.readFileSync(this._path).toString() || "{}");
                Object.entries(raw).forEach(([key, value]) => {
                    this._data.set(key, value as CombinedFingerprint);
                });
                console.info(`supercookie | Loaded ${this._data.size} fingerprints from storage`);
            }
        } catch (e) {
            console.error(`supercookie | Failed to load fingerprints:`, e);
        }
    }

    private save(): void {
        try {
            const obj: Record<string, CombinedFingerprint> = {};
            this._data.forEach((value, key) => obj[key] = value);
            fs.writeFileSync(this._path, JSON.stringify(obj, null, '\t'));
        } catch (e) {
            console.error(`supercookie | Failed to save fingerprints:`, e);
        }
    }

    public set(uid: string, fp: CombinedFingerprint): void {
        this._data.set(uid, fp);
        this.save();
    }

    public get(uid: string): CombinedFingerprint | undefined {
        return this._data.get(uid);
    }

    public has(uid: string): boolean {
        return this._data.has(uid);
    }

    public findByHash(hash: string): CombinedFingerprint | undefined {
        for (const fp of this._data.values()) {
            if (fp.combinedHash === hash) return fp;
        }
        return undefined;
    }

    public findByFaviconId(faviconId: number): CombinedFingerprint | undefined {
        for (const fp of this._data.values()) {
            if (fp.faviconIdentifier === faviconId) return fp;
        }
        return undefined;
    }

    public getStats(): { total: number; withFavicon: number; withClient: number } {
        let withFavicon = 0, withClient = 0;
        this._data.forEach(fp => {
            if (fp.faviconIdentifier !== null) withFavicon++;
            if (fp.clientFingerprint !== null) withClient++;
        });
        return { total: this._data.size, withFavicon, withClient };
    }
}

const persistentFingerprintStore = new FingerprintStorage();

dotenv.config();

/****************************************************************************************************\
 * @global
 * User options (edit in .env file)
 */
const WEBSERVER_DOMAIN_1: string    = process.env["HOST_MAIN"] ?? "localhost:10080";
const WEBSERVER_DOMAIN_2: string    = process.env["HOST_DEMO"] ?? "localhost:10081";
const WEBSERVER_PORT_1: number      = +process.env["PORT_MAIN"] ?? 10080;
const WEBSERVER_PORT_2: number      = +process.env["PORT_DEMO"] ?? 10081;
const CACHE_IDENTIFIER: string      = STORAGE.cacheID ?? generateUUID("xxxxxxxx", "0123456789abcdef");

const N: number                     = 32; // max 2^N unique ids possible
/*****************************************************************************************************/


const FILE = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+ip1sAAAAASUVORK5CYII=";
const webserver_1: express.Express = express();
const webserver_2: express.Express = express();
const maxN: number = 2**N - 1;

webserver_1.options('*', cors());
webserver_2.options('*', cors());

console.info(`supercookie | Starting up using N=${N}, C-ID='${CACHE_IDENTIFIER}' ...`);
console.info(`supercookie | There are ${Math.max(maxN - 1 - (STORAGE.index ?? 1), 0)}/${maxN-1} unique identifiers left.`);


/**
 * @class Webserver
 * Webserver defaults
 */
class Webserver {
    public static routes: Array<string> = createRoutes(CACHE_IDENTIFIER, N).map((value: string) => `${CACHE_IDENTIFIER}:${value}`);
    
    public static getVector(identifier: number): Array<string> {
        const booleanVector: Array<boolean> = (identifier >>> 0).toString(2)
            .padStart(this.routes.length, '0').split('')
            .map((element: '0' | '1') => element === '1')
            .reverse();
        const vector = new Array<string>();
        booleanVector.forEach((value: boolean, index: number) => value ? vector.push(this.getRouteByIndex(index)) : void 0);
        return vector;
    }
    public static getIdentifier(vector: Set<string>, size: number = vector.size): number {
        return parseInt(this.routes.map((route: string) => vector.has(route) ? 0 : 1)
            .join('').slice(0, size).split('').reverse().join(''), 2);
    }
    public static hasRoute(route: string): boolean {
        return this.routes.includes(route);
    }
    public static getRouteByIndex(index: number): string {
        return this.routes[index] ?? null;
    }
    public static getIndexByRoute(route: string): number {
        return this.routes.indexOf(route) ?? null;
    }
    public static getNextRoute(route: string): string | null {
        const index = this.routes.indexOf(route);
        if (index === -1)
            throw "Route is not valid.";
        return this.getRouteByIndex(index+1);
    }
    public static setCookie(res: express.Response,
                            name: string, value: any, 
                            options: express.CookieOptions = { httpOnly: false, expires: new Date(Date.now() + 60 * 1000) }): express.Response {
        return res.cookie(name, value, options), res;
    }
    public static sendFile( res: express.Response, 
                            route: string, options: any = {}, type: string = "html"): express.Response {
        let content = fs.readFileSync(route).toString();
        Object.keys(options).sort((a: string, b: string) => b.length - a.length).forEach((key: string) => {
            content = content.replace(
                new RegExp(`\{\{${key}\}\}`, 'g'), 
                (options[key]?.toString() || '')
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;")
            );
        });
        res.header({
            "Cache-Control": "private, no-cache, no-store, must-revalidate",
            "Expires": -1,
            "Pragma": "no-cache"
        });
        res.type(type);
        return res.send(content), res;
    }
}

/**
 * @class Profile
 * Read / Write class
 */
class Profile {
    public static list: Set<Profile> = new Set<Profile>();
    public static get(uid: string): Profile {
        return this.has(uid) ? 
            Array.from(this.list).filter((profile: Profile) => profile.uid === uid)?.pop(): 
            null;
    }
    public static has(uid: string): boolean {
        return Array.from(this.list).some((profile: Profile) => profile.uid === uid);
    }
    public static from(uid: string, identifier?: number): Profile {
        return !this.has(uid) ? new Profile(uid, identifier): null;
    }

    private _uid: string;
    private _vector: Array<string>;
    private _identifier: number = null;
    private _visitedRoutes: Set<string> = new Set<string>();
    private _storageSize: number = -1;

    constructor(uid: string, identifier: number = null) {
        this._uid = uid;
        if (identifier !== null) 
            this._identifier = identifier,
            this._vector = Webserver.getVector(identifier);
        Profile.list.add(this);
    }
    public destructor() {
        Profile.list.delete(this);
    }
    public get uid(): string {
        return this._uid;
    }
    public get vector(): Array<string> {
        return this._vector;
    }
    public get visited(): Set<string> {
        return this._visitedRoutes;
    }
    public get identifier(): number {
        return this._identifier;
    }
    public getRouteByIndex(index: number): string {
        return this.vector[index] ?? null;
    }
    public _isReading(): boolean {
        return this._identifier === null;
    }
    public _visitRoute(route: string) {
        this._visitedRoutes.add(route);
    }
    public _calcIdentifier(): number {
        return this._identifier = Webserver.getIdentifier(this._visitedRoutes, this._storageSize), this.identifier;
    }
    public _setStorageSize(size: number) {
        this._storageSize = size;
    }
    public get storageSize(): number {
        return this._storageSize;
    }
};

webserver_2.set("trust proxy", 1);
webserver_2.use(cookieParser());
webserver_2.use((req: express.Request, res: express.Response, next: Function) => {  
    if (new RegExp(`https?:\/\/${WEBSERVER_DOMAIN_2}`).test(req.headers.origin))
        res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
    res.header("Access-Control-Allow-Methods", "GET, OPTIONS");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    return next();
});


/**
 * @description
 * Using token based "write authentification" to avoid spam to /write path
 */
const midSet: Set<string> = new Set<string>();
const generateWriteToken = (): string => {
    const uuid = generateUUID();
    setTimeout(() => midSet.delete(uuid), 1_000 * 60);
    return midSet.add(uuid), uuid;
}
const deleteWriteToken = (token: string) => midSet.delete(token);
const hasWriteToken = (token: string): boolean => midSet.has(token);

/**
 * @description
 * When navigating to path /read the mode of an (known) visitor is set to "write". 
 * Assuming that the data has already been written to the browser, the webserver
 * is redirecting the user to the first route.
 */
webserver_2.get("/read", (_req: express.Request, res: express.Response) => {
    const uid = generateUUID();
    console.info(`supercookie | Visitor uid='${uid}' is known • Read`);
    const profile: Profile = Profile.from(uid);
    profile._setStorageSize(Math.floor(Math.log2(STORAGE.index ?? 1)) + 1);
    if (profile === null)
        return res.redirect("/read");
    Webserver.setCookie(res, "uid", uid);
    res.redirect(`/t/${Webserver.getRouteByIndex(0)}?f=${generateUUID()}`)
});

/**
 * @description
 * If a user navigates to path /write a new (unknown) visitor entry is created.
 * Assuming that the data has not been written to the browser, the webserver
 * is redirecting the user to the first route.
 */
webserver_2.get("/write/:mid", (req: express.Request, res: express.Response) => {
    const mid = req.params.mid;
    if (!hasWriteToken(mid))
        return res.redirect('/');
    res.clearCookie("mid");
    deleteWriteToken(mid);
    const uid = generateUUID();
    console.info(`supercookie | Visitor uid='${uid}' is unknown • Write`, STORAGE.index);
    const profile: Profile = Profile.from(uid, STORAGE.index);
    if (profile === null)
        return res.redirect('/');
    STORAGE.index++;
    Webserver.setCookie(res, "uid", uid);
    res.redirect(`/t/${Webserver.getRouteByIndex(0)}`);
});

/**
 * @description
 * Under the /t path, the user is redirected to the next possible route.
 */
webserver_2.get("/t/:ref", (req: express.Request, res: express.Response) => {
    const referrer: string = req.params.ref;
    const uid: string = req.cookies.uid;
    const profile: Profile = Profile.get(uid);

    if (!Webserver.hasRoute(referrer) || profile === null)
        return res.redirect('/');
    const route: string = Webserver.getNextRoute(referrer);

    /** reload issue */
    if (profile._isReading() && profile.visited.has(referrer))
        return res.redirect('/');
    let nextReferrer: string = null;
    const redirectCount: number = profile._isReading() ? 
        profile.storageSize: 
        Math.floor(Math.log2(profile.identifier)) + 1;

    if (route) 
        nextReferrer = `t/${route}?f=${generateUUID()}`;
    if (!profile._isReading()) {
        if (Webserver.getIndexByRoute(referrer) >= redirectCount - 1)
            nextReferrer = "read";
    } else if (Webserver.getIndexByRoute(referrer) >= redirectCount - 1 || nextReferrer === null)
        nextReferrer = "identity";

    const bit = !profile._isReading() ? profile.vector.includes(referrer) : "{}";
    Webserver.sendFile(res, path.join(path.resolve(), "www/referrer.html"), {
        delay: profile._isReading() ? 500 : 800,
        referrer: nextReferrer,
        favicon: referrer,
        bit: bit,
        index: `${Webserver.getIndexByRoute(referrer)+1} / ${redirectCount}`
    });
});

/**
 * @description
 * After finishing the reading process, the browser is redirected to the /identity route.
 * Here, the browser is assigned the calculated identifier and displayed to the user.
 * Now also links with collected fingerprint data for Safari 17+ compatibility.
 */
webserver_2.get("/identity", (req: express.Request, res: express.Response) => {
    const uid: string = req.cookies.uid;
    const profile: Profile = Profile.get(uid);
    if (profile === null)
        return res.redirect('/');
    res.clearCookie("uid");
    res.clearCookie("vid");
    const identifier = profile._calcIdentifier();

    // Link favicon identifier with fingerprint store (memory + persistent)
    if (fingerprintStore.has(uid)) {
        const fpData = fingerprintStore.get(uid);
        fpData.faviconIdentifier = identifier;
        persistentFingerprintStore.set(uid, fpData); // Persist the link
        console.info(`supercookie | Linked fingerprint hash='${fpData.combinedHash}' with favicon ID #${identifier}`);
    }

    // Collect server-side fingerprint for this request (Safari 17+ fallback)
    const serverFp = extractServerFingerprint(req);
    const serverHash = hashFingerprint(serverFp);

    if (identifier === maxN || profile.visited.size === 0 || identifier === 0)
        return res.redirect(`/write/${generateWriteToken()}`);
    if (identifier !== 0) {
        const identifierHash: string = hashNumber(identifier);
        console.info(`supercookie | Visitor successfully identified as '${identifierHash}' • (#${identifier}) • server-fp='${serverHash}'`);
        Webserver.sendFile(res, path.join(path.resolve(), "www/identity.html"), {
            hash: identifierHash,
            identifier: `#${identifier}`,

            url_workwise: `${WEBSERVER_DOMAIN_1}/workwise`,
            url_main: WEBSERVER_DOMAIN_1
        });
    } else Webserver.sendFile(res, path.join(path.resolve(), "www/identity.html"), {
        hash: "AN ON YM US",
        identifier: "browser not vulnerable",

        url_workwise: `${WEBSERVER_DOMAIN_1}/workwise`,
        url_main: WEBSERVER_DOMAIN_1
    });
});

/**
 * @description
 * Fixing a chrome (v 87.0) problem using javascript redirect instead of 
 * express redirect (in redirect.html)
 */
webserver_2.get(`/${CACHE_IDENTIFIER}`, (req: express.Request, res: express.Response) => {
    const rid: boolean = !!req.cookies.rid;
    res.clearCookie("rid");
    if (!rid) 
        Webserver.sendFile(res, path.join(path.resolve(), "www/redirect.html"), {
            url_demo: WEBSERVER_DOMAIN_2
        });
    else
        Webserver.sendFile(res, path.join(path.resolve(), "www/launch.html"), {
            favicon: CACHE_IDENTIFIER
        });
});

/**
 * @description
 * Main route / is redirecting to /CACHE_IDENTIFIER
 */
webserver_2.get('/', (_req: express.Request, res: express.Response) => {
    Webserver.setCookie(res, "rid", true);
    res.clearCookie("mid");
    res.redirect(`/${CACHE_IDENTIFIER}`);
});

/**
 * @description
 * When requesting the favicon under /l, it is excluded that a user already has valid data in the cache.
 */
webserver_2.get("/l/:ref", (_req: express.Request, res: express.Response) => {
    console.info(`supercookie | Unknown visitor detected.`);
    Webserver.setCookie(res, "mid", generateWriteToken());
    const data = Buffer.from(FILE, "base64");
    res.writeHead(200, {
        "Cache-Control": "public, max-age=31536000",
        "Expires": new Date(Date.now() + 31536000000).toUTCString(),
        "Content-Type": "image/png",
        "Content-Length": data.length
    });
    res.end(data);
});


webserver_2.get("/i/:ref", (req: express.Request, res: express.Response) => {
    const data = Buffer.from(FILE, "base64");
    res.writeHead(200, {
        "Cache-Control": "public, max-age=31536000",
        "Expires": new Date(Date.now() + 31536000000).toUTCString(),
        "Content-Type": "image/png",
        "Content-Length": data.length
    });
    res.end(data);
});
/**
 * @description
 * /f route handles requests for favicons by the browser.
 * In write mode, some icons are delivered and other requests are aborted. 
 * In read mode every request fails to not corrupt the cache.
 */
webserver_2.get("/f/:ref", (req: express.Request, res: express.Response) => {
    const referrer: string = req.params.ref;
    const uid: string = req.cookies.uid;
    if (!Profile.has(uid) || !Webserver.hasRoute(referrer))
        return res.status(404), res.end();
    const profile: Profile = Profile.get(uid);
    if (profile._isReading()) {
        profile._visitRoute(referrer);
        console.info(`supercookie | Favicon requested by uid='${uid}' • Read `, Webserver.getIndexByRoute(referrer), "•", 
            Array.from(profile.visited).map(route => Webserver.getIndexByRoute(route)));
        return; // res.type("gif"), res.status(404), res.end();
    }
    if (!profile.vector.includes(referrer)) {
        console.info(`supercookie | Favicon requested by uid='${uid}' • Write`, Webserver.getIndexByRoute(referrer), "•", 
            Array.from(profile.vector).map(route => Webserver.getIndexByRoute(route)));
        return; // res.type("gif"), res.status(404), res.end();
    }
    const data = Buffer.from(FILE, "base64");
    res.writeHead(200, {
        "Cache-Control": "public, max-age=31536000",
        "Expires": new Date(Date.now() + 31536000000).toUTCString(),
        "Content-Type": "image/png",
        "Content-Length": data.length
    });
    res.end(data);
});

webserver_1.use("/assets", express.static(path.join(path.resolve(), "www/assets"), { index: false }));
webserver_2.use("/assets", express.static(path.join(path.resolve(), "www/assets"), { index: false }));
webserver_1.get('/', (_req: express.Request, res: express.Response) => {
    Webserver.sendFile(res, path.join(path.resolve(), "www/index.html"), {
        url_demo: WEBSERVER_DOMAIN_2
    });
});
webserver_1.get("/favicon.ico", (_req: express.Request, res: express.Response) => {
    res.sendFile(path.join(path.resolve(), "www/favicon.ico"));
});
webserver_2.get("/favicon.ico", (_req: express.Request, res: express.Response) => {
    res.sendFile(path.join(path.resolve(), "www/favicon.ico"));
});
webserver_1.get("/workwise", (_req: express.Request, res: express.Response) => {
    Webserver.sendFile(res, path.join(path.resolve(), "www/workwise.html"), {
        url_main: WEBSERVER_DOMAIN_1
    });
});
webserver_1.get("/api", (_req: express.Request, res: express.Response) => {
    res.type("json");
    res.status(200);
    res.send({
        index: STORAGE.index,
        cache: STORAGE.cacheID,
        bits: Math.floor(Math.log2(STORAGE.index ?? 1)) + 1,
        N: N,
        maxN: maxN
    });
});

/**
 * @description
 * API endpoint to receive client-side fingerprint data
 * Safari 17+ blocks some client APIs, so we combine with server-side signals
 */
webserver_2.use(express.json());
webserver_2.post("/api/fingerprint", (req: express.Request, res: express.Response) => {
    const uid: string = req.cookies.uid || generateUUID();
    const clientData: ClientSideFingerprint = req.body;
    const serverData = extractServerFingerprint(req);

    // Combine server + client fingerprints
    const combinedData = {
        server: {
            userAgent: serverData.userAgent,
            acceptLanguage: serverData.acceptLanguage,
            ip: serverData.ipAddress,
            ja3: serverData.ja3Hash,
            ja4: serverData.ja4Hash,
            secChUa: serverData.secChUa,
            secChUaPlatform: serverData.secChUaPlatform
        },
        client: clientData
    };

    const combinedHash = hashFingerprint(combinedData);

    const fpRecord: CombinedFingerprint = {
        uid,
        serverFingerprint: serverData,
        clientFingerprint: clientData,
        faviconIdentifier: null,
        combinedHash,
        timestamp: Date.now()
    };

    // Store in both memory and persistent storage
    fingerprintStore.set(uid, fpRecord);
    persistentFingerprintStore.set(uid, fpRecord);

    // Check if this fingerprint hash matches a known user (Safari 17+ re-identification)
    const existingByHash = persistentFingerprintStore.findByHash(combinedHash);
    if (existingByHash && existingByHash.uid !== uid && existingByHash.faviconIdentifier) {
        console.info(`supercookie | Safari 17+ re-identification: hash='${combinedHash}' matches known user #${existingByHash.faviconIdentifier}`);
    }

    console.info(`supercookie | Fingerprint collected for uid='${uid}' hash='${combinedHash}'`);

    res.type("json");
    res.status(200);
    res.send({
        success: true,
        uid,
        hash: combinedHash,
        serverSignals: Object.keys(serverData).filter(k => (serverData as any)[k] !== null).length,
        clientSignals: clientData ? Object.keys(clientData).length : 0
    });
});

/**
 * @description
 * API endpoint to get server-side fingerprint info (useful for debugging)
 */
webserver_2.get("/api/fingerprint", (req: express.Request, res: express.Response) => {
    const serverData = extractServerFingerprint(req);
    const serverHash = hashFingerprint(serverData);

    res.type("json");
    res.status(200);
    res.send({
        hash: serverHash,
        fingerprint: serverData,
        safari17Note: "Screen resolution and screen frame unavailable on Safari 17+. Use server-side signals.",
        tlsNote: serverData.ja3Hash ? "JA3/JA4 available" : "Configure reverse proxy to pass X-JA3-Fingerprint header"
    });
});

/**
 * @description
 * API endpoint to view fingerprint storage stats
 */
webserver_2.get("/api/fingerprint/stats", (_req: express.Request, res: express.Response) => {
    const stats = persistentFingerprintStore.getStats();
    res.type("json");
    res.status(200);
    res.send({
        ...stats,
        faviconVisitors: STORAGE.index ?? 1,
        safari17Coverage: stats.total > 0 ? ((stats.withClient / stats.total) * 100).toFixed(1) + '%' : '0%'
    });
});

/**
 * @description
 * Serves the client-side fingerprint collector script
 */
webserver_2.get("/api/collector.js", (_req: express.Request, res: express.Response) => {
    res.type("application/javascript");
    res.send(`
/**
 * Supercookie Client Fingerprint Collector
 * Collects browser signals and sends to server
 * Note: Safari 17+ blocks screen.width/height (returns document size)
 */
(function() {
    'use strict';

    const collectFingerprint = async () => {
        const fp = {
            // Screen (Safari 17+ returns document size, but collect anyway)
            screenWidth: window.screen.width,
            screenHeight: window.screen.height,
            screenAvailWidth: window.screen.availWidth,
            screenAvailHeight: window.screen.availHeight,
            screenColorDepth: window.screen.colorDepth,
            devicePixelRatio: window.devicePixelRatio || 1,

            // Window dimensions
            innerWidth: window.innerWidth,
            innerHeight: window.innerHeight,
            outerWidth: window.outerWidth,
            outerHeight: window.outerHeight,

            // Navigator properties
            hardwareConcurrency: navigator.hardwareConcurrency || 0,
            deviceMemory: navigator.deviceMemory || null,
            maxTouchPoints: navigator.maxTouchPoints || 0,
            language: navigator.language,
            languages: Array.from(navigator.languages || []),
            platform: navigator.platform,
            vendor: navigator.vendor,
            cookieEnabled: navigator.cookieEnabled,
            doNotTrack: navigator.doNotTrack,

            // Timezone
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            timezoneOffset: new Date().getTimezoneOffset(),

            // WebGL fingerprint
            webglVendor: null,
            webglRenderer: null,

            // Hashes (computed below)
            canvasHash: null,
            audioHash: null,
            fontsHash: null,

            // Feature detection
            webrtcEnabled: !!window.RTCPeerConnection,
            indexedDbEnabled: !!window.indexedDB,
            sessionStorageEnabled: !!window.sessionStorage,
            localStorageEnabled: !!window.localStorage
        };

        // WebGL fingerprint
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (gl) {
                const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                if (debugInfo) {
                    fp.webglVendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
                    fp.webglRenderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
                }
            }
        } catch (e) {}

        // Canvas fingerprint (with 3x3 scaling to defeat Safari noise clamping)
        try {
            // Safari 17+ adds noise clamped to neighboring pixels
            // By scaling 3x3 and reading center pixels, we recover original values
            const scale = 3;
            const baseW = 200, baseH = 50;
            const canvas = document.createElement('canvas');
            canvas.width = baseW * scale;
            canvas.height = baseH * scale;
            const ctx = canvas.getContext('2d');
            if (ctx) {
                ctx.scale(scale, scale);
                ctx.textBaseline = 'alphabetic';
                ctx.fillStyle = '#f60';
                ctx.fillRect(125, 1, 62, 20);
                ctx.fillStyle = '#069';
                ctx.font = '11pt Arial';
                ctx.fillText('Cwm fjordbank glyphs vext quiz', 2, 15);
                ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
                ctx.font = '18pt Arial';
                ctx.fillText('Cwm fjordbank glyphs vext quiz', 4, 45);

                // Extract center pixels from each 3x3 block to defeat noise
                const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                const centerPixels = [];
                for (let y = 1; y < canvas.height; y += scale) {
                    for (let x = 1; x < canvas.width; x += scale) {
                        const idx = (y * canvas.width + x) * 4;
                        centerPixels.push(
                            imageData.data[idx],
                            imageData.data[idx + 1],
                            imageData.data[idx + 2],
                            imageData.data[idx + 3]
                        );
                    }
                }

                // Hash the center pixels (noise-free)
                let hash = 0;
                for (let i = 0; i < centerPixels.length; i++) {
                    hash = ((hash << 5) - hash) + centerPixels[i];
                    hash = hash & hash;
                }
                fp.canvasHash = hash.toString(16);
            }
        } catch (e) {}

        // Audio fingerprint
        try {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioContext.createOscillator();
            const analyser = audioContext.createAnalyser();
            const gain = audioContext.createGain();
            const scriptProcessor = audioContext.createScriptProcessor(4096, 1, 1);

            oscillator.type = 'triangle';
            oscillator.frequency.setValueAtTime(10000, audioContext.currentTime);
            gain.gain.setValueAtTime(0, audioContext.currentTime);

            oscillator.connect(analyser);
            analyser.connect(scriptProcessor);
            scriptProcessor.connect(gain);
            gain.connect(audioContext.destination);

            oscillator.start(0);

            const fingerprint = await new Promise((resolve) => {
                scriptProcessor.onaudioprocess = (event) => {
                    const output = event.inputBuffer.getChannelData(0);
                    let sum = 0;
                    for (let i = 0; i < output.length; i++) {
                        sum += Math.abs(output[i]);
                    }
                    oscillator.disconnect();
                    scriptProcessor.disconnect();
                    resolve(sum.toString(16).slice(0, 8));
                };
            });
            fp.audioHash = fingerprint;
            audioContext.close();
        } catch (e) {}

        // Font detection (works on Safari 17+)
        try {
            const baseFonts = ['monospace', 'sans-serif', 'serif'];
            const testFonts = [
                'Arial', 'Arial Black', 'Comic Sans MS', 'Courier New', 'Georgia',
                'Impact', 'Lucida Console', 'Lucida Sans Unicode', 'Palatino Linotype',
                'Tahoma', 'Times New Roman', 'Trebuchet MS', 'Verdana',
                'Helvetica', 'Helvetica Neue', 'Monaco', 'Menlo', 'SF Pro',
                'Roboto', 'Open Sans', 'Lato', 'Montserrat', 'Source Sans Pro'
            ];
            const testString = 'mmmmmmmmmmlli';
            const testSize = '72px';
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');

            const getWidth = (font) => {
                ctx.font = testSize + ' ' + font;
                return ctx.measureText(testString).width;
            };

            const baseWidths = {};
            baseFonts.forEach(f => baseWidths[f] = getWidth(f));

            const detected = [];
            testFonts.forEach(font => {
                const found = baseFonts.some(base => {
                    return getWidth(font + ',' + base) !== baseWidths[base];
                });
                if (found) detected.push(font);
            });

            // Hash the detected fonts
            let hash = 0;
            const fontStr = detected.join(',');
            for (let i = 0; i < fontStr.length; i++) {
                hash = ((hash << 5) - hash) + fontStr.charCodeAt(i);
                hash = hash & hash;
            }
            fp.fontsHash = hash.toString(16);
        } catch (e) {}

        return fp;
    };

    // Send fingerprint to server
    const sendFingerprint = async () => {
        try {
            const fp = await collectFingerprint();
            const response = await fetch('/api/fingerprint', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(fp),
                credentials: 'include'
            });
            return await response.json();
        } catch (e) {
            console.error('Fingerprint collection failed:', e);
            return null;
        }
    };

    // Export
    window.SupercookieCollector = { collect: collectFingerprint, send: sendFingerprint };

    // Auto-send on load if configured
    if (document.currentScript && document.currentScript.dataset.autoSend === 'true') {
        sendFingerprint();
    }
})();
`);
});

webserver_1.get('*', (_req: express.Request, res: express.Response) => {
    res.redirect('/');
});
webserver_2.get('*', (req: express.Request, res: express.Response) => {
    Webserver.sendFile(res, path.join(path.resolve(), "www/404.html"), {
        path: decodeURIComponent(req.path),
        url_main: WEBSERVER_DOMAIN_1
    });
});

webserver_1.listen(WEBSERVER_PORT_1, () => 
    console.info(`express-web | Webserver-1 for '${WEBSERVER_DOMAIN_1}' running on port:`, WEBSERVER_PORT_1));
webserver_2.listen(WEBSERVER_PORT_2, () => 
    console.info(`express-web | Webserver-2 for '${WEBSERVER_DOMAIN_2}' running on port:`, WEBSERVER_PORT_2));
STORAGE.index = STORAGE.index ?? 1;
STORAGE.cacheID = CACHE_IDENTIFIER;