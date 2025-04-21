import axios from 'axios';
import geoip from 'geoip-lite';
import stringSimilarity from 'string-similarity';

const KNOWN_BOT_ISPS = [ 
  "cogent communications, inc.",
  "c-lutions inc",
  "worldstream bv",
  "amazon.com",
  "global secure layer",
  "rgt/smp",
  "tzulo inc",
  "cyber assets fzco",
  "falco networks b.v.",
  "pjsc rostelecom",
  "gtd internet s.a.",
  "meta networks inc",
  "private layer inc",
  "bucklog sarl",
  "fbw reseaux fibres inc",
  "openvpn",
  "huawei cloud hongkong region",
  "excitel broadband pvt ltd",
  "vpn consumer frankfurt germany",
  "m nets sal",
  "hostroyale technologies pvt ltd",
  "the constant company llc",
  "bgm",
  "microcom informatique inc",
  "contabo inc",
  "telecable residencial",
  "network for tor-exit traffic",
  "logicweb inc",
  "microsoft corp",
  "microsoft corporation",
  "microsoft limited",
  "microsoft",
  "google llc",
  "unknown",
  "barry hamel equipment ltd",
  "charter communications",
  "dlf cable network",
  "packethub s.a.",
  "datacamp s.r.o.",
  "bharti airtel limited",
  "clouvider",
  "facebook",
  "internet archive",
  "quickpacket llc",
  "amazon data services singapore",
  "pjsc mts sverdlovsk region",
  "home_dsl",
  "amazon data services nova",
  "m247 ltd berlin infrastructure",
  "bretagne telecom sasu",
  "m247 ltd - brazil infrastructure",
  "zap-hosting.com - if you want more power",
  "zap-hosting gmbh",
  "artic solutions sarl",
  "ucloud",
  "cox communications inc",
  "onyphe sas",
  "internet utilities europe and asia limited",
  "kyocera avx components (dresden) gmbh",
  "blix group as",
  "kaopu cloud hk limited",
  "total server solutions llc",
  "internet utilities africa (pty) ltd",
  "atria convergence technologies ltd",
  "linode",
  "linode llc",
  "bayer ag germany leverkusen",
  "terago networks inc",
  "zscaler inc",
  "bt global communications india private limited-access",
  "not surf net",
  "nothing to hide",
  "total play telecomunicaciones sa de cv",
  "driftnet ltd",
  "telstra limited",
  "ovh us llc",
  "tt dotcom sdn bhd",
  "ovh (nwk)",
  "ovh sas",
  "ovh hosting inc",
  "zayo bandwidth",
  "accenture llp",
  "kyivstar gsm",
  "cascades",
  "netcraft",
  "rockion llc",
  "sudhana telecommunications private limited",
  "compass compression services ltd",
  "digitalocean",
  "amazon technologies inc",
  "datacamp limited",
  "helsinki finland",
  "northerntel limited partnership",
  "china unicom shandong province network",
  "china unicom shanghai city network",
  "china unicom henan province network",
  "kddi corporation",
  "reliance jio infocomm limited",
  "hetzner online gmbh",
  "alibaba",
  "oracle corporation",
  "softlayer technologies",
  "fastly",
  "cloudflare",
  "cloudflare london llc",
  "akamai technologies",
  "akamai technologies inc",
  "hurricane electric",
  "hostwinds",
  "choopa",
  "contabo gmbh",
  "leaseweb",
  "leaseweb deutschland gmbh",
  "censys inc",
  "windscribe",
  "hatching international b.v.",
  "asm technologies",
  "amazon.com inc",
  "amazon data services ireland limited",
  "scaleway",
  "vultr",
  "ubiquity" ];
const KNOWN_BOT_ASNS = ['AS16509', 'AS14061', 'AS13335', /* etc */ ];

const TRAFFIC_THRESHOLD = 10;
const TRAFFIC_TIMEFRAME = 30 * 1000;
const TRAFFIC_DATA = {};
const ISP_SIMILARITY_THRESHOLD = 0.7;

function fuzzyMatchISP(isp) {
  const match = stringSimilarity.findBestMatch(isp.toLowerCase(), KNOWN_BOT_ISPS);
  return match.bestMatch.rating > ISP_SIMILARITY_THRESHOLD;
}

async function checkIPReputation(ip) {
  try {
    const res = await axios.get(`https://api.abuseipdb.com/api/v2/check`, {
      headers: { Key: '000a4d9049d8d08013a3c7c18fe33a84a31075d8b1aa19cd0232078bfa68bccb3bb326bc2444cefd', Accept: 'application/json' },
      params: { ipAddress: ip, maxAgeInDays: 30 }
    });

    return res.data.data.abuseConfidenceScore >= 50;
  } catch {
    return false;
  }
}

function analyzeHeaders(headers) {
  const suspiciousHeaders = [
    'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-dest', 'sec-ch-ua', 'sec-ch-ua-platform'
  ];
  return suspiciousHeaders.some(h => !headers[h]);
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'OPTIONS, POST');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { user_agent, ip, fingerprint_score } = req.body;
  const headers = req.headers;

  if (!ip || !user_agent) {
    return res.status(400).json({ error: 'Missing required fields.' });
  }

  const botPatterns = [/bot/, /crawl/, /scraper/, /spider/, /httpclient/, /python/];
  const isBotUserAgent = botPatterns.some(p => p.test(user_agent.toLowerCase()));

  // AbuseIPDB Score
  const isIPAbuser = await checkIPReputation(ip);

  // Geo + ISP Logic using ipgeolocation.io
  let isp = 'unknown', asn = 'unknown', country = 'unknown';
  try {
    const GEO_API_KEY = 'dcd7f3c53127433686c5b29f8b0debf6'; // Replace this
    const geoRes = await axios.get(`https://api.ipgeolocation.io/ipgeo`, {
      params: {
        apiKey: GEO_API_KEY,
        ip: ip
      }
    });

    isp = geoRes.data?.isp?.toLowerCase() || 'unknown';
    asn = geoRes.data?.asn || 'unknown';
    country = geoRes.data?.country_name || 'unknown';
  } catch (err) {
    const geoData = geoip.lookup(ip);
    country = geoData?.country || 'unknown';
  }

  const isScraperISP = fuzzyMatchISP(isp);
  const isDataCenterASN = KNOWN_BOT_ASNS.includes(asn);

  // Traffic behavior
  const now = Date.now();
  if (!TRAFFIC_DATA[ip]) TRAFFIC_DATA[ip] = [];
  TRAFFIC_DATA[ip] = TRAFFIC_DATA[ip].filter(ts => now - ts < TRAFFIC_TIMEFRAME);
  TRAFFIC_DATA[ip].push(now);
  const isSuspiciousTraffic = TRAFFIC_DATA[ip].length > TRAFFIC_THRESHOLD;

  // Header fingerprinting
  const isMissingHeaders = analyzeHeaders(headers);
  const isLowFingerprintScore = fingerprint_score !== undefined && fingerprint_score < 0.3;

  // Final Decision
  const riskFactors = [
    isBotUserAgent,
    isScraperISP,
    isIPAbuser,
    isDataCenterASN,
    isSuspiciousTraffic,
    isMissingHeaders,
    isLowFingerprintScore
  ];

  const score = riskFactors.filter(Boolean).length / riskFactors.length;
  const isBot = score >= 0.5;

  res.status(200).json({
    is_bot: isBot,
    score,
    country,
    details: {
      isp, asn, user_agent,
      isBotUserAgent,
      isScraperISP,
      isIPAbuser,
      isSuspiciousTraffic,
      isDataCenterASN,
      isMissingHeaders,
      isLowFingerprintScore
    }
  });
}
