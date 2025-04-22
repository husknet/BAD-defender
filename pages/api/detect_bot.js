import axios from 'axios';
import geoip from 'geoip-lite';
import stringSimilarity from 'string-similarity';

const KNOWN_BOT_ISPS = [
  // ✅ Keep your list as is
  "RGT/SMP", "tzulo, inc.", "Cyber Assets FZCO", "Falco Networks B.V.", "Google LLC",
  "DigitalOcean", "OVH SAS", "Cloudflare", "Hetzner Online GmbH", "Amazon.com, Inc.", 
  "scaleway", "vultr", "ubiquity"
];

const KNOWN_BOT_ASNS = ['AS16509', 'AS14061', 'AS13335']; // ✅ Add more as needed

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
    const res = await axios.get("https://api.abuseipdb.com/api/v2/check", {
      headers: {
        Key: '000a4d9049d8d08013a3c7c18fe33a84a31075d8b1aa19cd0232078bfa68bccb3bb326bc2444cefd',
        Accept: 'application/json'
      },
      params: { ipAddress: ip, maxAgeInDays: 30 },
      timeout: 4000
    });
    return res.data.data.abuseConfidenceScore >= 50;
  } catch (error) {
    console.error("❌ AbuseIPDB failed:", error.message);
    return false;
  }
}

function analyzeHeaders(headers) {
  const suspiciousHeaders = [
    'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-dest',
    'sec-ch-ua', 'sec-ch-ua-platform'
  ];
  return suspiciousHeaders.some(h => !headers[h]);
}

export default async function handler(req, res) {
  try {
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

    const isIPAbuser = await checkIPReputation(ip);

    let isp = 'unknown', asn = 'unknown', country = 'unknown';
    try {
      const geoRes = await axios.get("https://api.ipgeolocation.io/ipgeo", {
        params: {
          apiKey: 'dcd7f3c53127433686c5b29f8b0debf6',
          ip: ip
        },
        timeout: 4000
      });

      isp = geoRes.data?.isp?.toLowerCase() || 'unknown';
      asn = geoRes.data?.asn || 'unknown';
      country = geoRes.data?.country_name || 'unknown';
    } catch (err) {
      console.error("❌ IPGeolocation failed:", err.message);
      const geoData = geoip.lookup(ip);
      country = geoData?.country || 'unknown';
    }

    const isScraperISP = fuzzyMatchISP(isp);
    const isDataCenterASN = KNOWN_BOT_ASNS.includes(asn);

    const now = Date.now();
    if (!TRAFFIC_DATA[ip]) TRAFFIC_DATA[ip] = [];
    TRAFFIC_DATA[ip] = TRAFFIC_DATA[ip].filter(ts => now - ts < TRAFFIC_TIMEFRAME);
    TRAFFIC_DATA[ip].push(now);
    const isSuspiciousTraffic = TRAFFIC_DATA[ip].length > TRAFFIC_THRESHOLD;

    const isMissingHeaders = analyzeHeaders(headers);
    const isLowFingerprintScore = fingerprint_score !== undefined && fingerprint_score < 0.3;

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

    return res.status(200).json({
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
  } catch (err) {
    console.error("🔥 UNEXPECTED ERROR:", err.message);
    return res.status(500).json({ error: "Internal server error" });
  }
}
