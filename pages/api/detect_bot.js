import axios from 'axios';
import geoip from 'geoip-lite';
import stringSimilarity from 'string-similarity';

const KNOWN_BOT_ISPS = [
  
  "RGT/SMP",
  "ophl",
  "m247 ltd new york",
  "hornetsecurity gmbh",
  "onyphe sas",
  "play fbb",
  "packethub s.a.",
  "internet security cheapyhost",
  "ippn holdings ltd",
  "satelcom internet inc.",
  "iway ag",
  "truview llc",
  "david prado rodriguez",
  "palo alto networks, inc",
  "driftnet.io",
  "vultr holdings, llc",
  "virtuo networks france",
  "amazon data services nova",
  "censys,inc.",
  "lantek llc",
  "ovh us llc",
  "egihosting",
  "hwc cable",
  "claro nxt telecomunicacoes ltda",
  "internet archive",
  "6 collyer quay",
  "cyberaccesdata inc.",
  "leaseweb canada inc.",
  "xinet solutions sa de cv",
  "aventice llc",
  "city west cable & telephone corp.",
  "optimum online cablevision systems",
  "ftn tilepikoinonies mepe",
  "techoff srv limited",
  "cloudflarenet eu",
  "tzulo, inc.",
  "Cyber Assets FZCO",
  "Falco Networks B.V.",
  "PJSC Rostelecom",
  "Gtd Internet S.A.",
  "Meta Networks Inc",
  "PRIVATE LAYER INC",
  "Bucklog SARL",
  "FBW Reseaux Fibres inc.",
  "OpenVPN",
  "Huawei Cloud Hongkong Region",
  "Excitel Broadband Pvt Ltd",
  "VPN Consumer Frankfurt, Germany",
  "M Nets SAL",
  "HostRoyale Technologies Pvt Ltd",
  "The Constant Company, LLC",
  "bgm",
  "Microcom Informatique, Inc.",
  "Contabo Inc",
  "TELECABLE RESIDENCIAL",
  "Network for Tor-Exit traffic.",
  "LogicWeb Inc.",
  "Microsoft Corp",
  "google llc",
  "Microsoft Corporation",
  "Contabo Inc.",
  "c-lutions inc",
  "Barry Hamel Equipment Ltd",
  "Charter Communications",
  "DLF Cable Network",
  "Packethub S.A.",
  "DataCamp s.r.o.",
  "Bharti Airtel Limited",
  "Clouvider",
  "Facebook",
  "Internet Archive",
  "QuickPacket, LLC",
  "Amazon Data Services Singapore",
  "PJSC MTS Sverdlovsk region",
  "HOME_DSL",
  "Amazon Data Services NoVa",
  "M247 LTD Berlin Infrastructure",
  "BRETAGNE TELECOM SASU",
  "M247 Ltd - Brazil Infrastructure",
  "ZAP-Hosting.com - IF YOU WANT MORE POWER",
  "ZAP-Hosting GmbH",
  "Artic Solutions SARL",
  "UCLOUD",
  "Cox Communications Inc.",
  "ONYPHE SAS",
  "Internet Utilities Europe and Asia Limited",
  "KYOCERA AVX Components (Dresden) GmbH",
  "Blix Group AS",
  "Kaopu Cloud HK Limited",
  "Cyber Assets FZCO",
  "Total server solutions LLC",
  "Internet Utilities Africa (PTY) LTD",
  "Atria Convergence Technologies Ltd.,",
  "Linode",
  "Bayer AG, Germany, Leverkusen",
  "TeraGo Networks Inc.",
  "Microsoft Corporation",
  "Zscaler, Inc.",
  "BT global Communications India Private Limited-Access",
  "Not SURF Net",
  "Nothing to hide",
  "TOTAL PLAY TELECOMUNICACIONES SA DE CV",
  "Driftnet Ltd",
  "Telstra Limited",
  "OVH US LLC",
  "TT DOTCOM SDN BHD",
  "OVH (NWK)",
  "Zayo Bandwidth",
  "Accenture LLP",
  "Kyivstar GSM",
  "Cascades",
  "Microsoft Limited",
  "Netcraft",
  "Rockion LLC",
  "Sudhana Telecommunications Private Limited",
  "COMPASS COMPRESSION SERVICES LTD",
  "DigitalOcean",
  "Amazon Technologies Inc.",
  "Google LLC",
  "Datacamp Limited",
  "Helsinki, Finland",
  "NorthernTel Limited Partnership",
  "China Unicom Shandong province network",
  "CHINA UNICOM Shanghai city network",
  "China Unicom Henan province network",
  "KDDI CORPORATION",
  "Reliance Jio Infocomm Limited",
  "Linode, LLC",
  "OVH SAS",
  "OVH Hosting, Inc.",
  "Hetzner Online GmbH",
  "Alibaba",
  "Oracle Corporation",
  "SoftLayer Technologies",
  "Fastly",
  "Cloudflare",
  "Cloudflare London, LLC",
  "Akamai Technologies",
  "Akamai Technologies Inc.",
  "Hurricane Electric",
  "Hostwinds",
  "Choopa",
  "Contabo GmbH",
  "Leaseweb",
  "Censys, Inc.",
  "Windscribe",
  "Hatching International B.V.",
  "Asm Technologies",
  "Leaseweb Deutschland GmbH",
  "Amazon.com, Inc.",
  "Amazon Data Services Ireland Limited",
  "Scaleway",
  "Vultr",
  "apnic research and development",
  "private customer",
  "Ubiquity"
];

const KNOWN_BOT_ASNS = ['AS16509', 'AS14061', 'AS13335', 'AS8075'];

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

    // ✅ Log everything to Railway console
    console.log("📥 Detection Log:");
    console.log("   IP:", ip);
    console.log("   Country:", country);
    console.log("   ISP:", isp);
    console.log("   ASN:", asn);
    console.log("   User-Agent:", user_agent);
    console.log("   Score:", score.toFixed(2), "| Bot:", isBot);
    console.log("   Flags:", {
      isBotUserAgent,
      isScraperISP,
      isIPAbuser,
      isDataCenterASN,
      isSuspiciousTraffic,
      isMissingHeaders,
      isLowFingerprintScore
    });

    return res.status(200).json({
      is_bot: isBot,
      score,
      country,
      details: {
        isp,
        asn,
        user_agent,
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
