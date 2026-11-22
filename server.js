const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { Readable } = require('stream');
const csv = require('csv-parser');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '10mb' }));
app.use(cors());

const publicDir = path.join(__dirname, 'public');
app.use(express.static(publicDir));

// Ana dizin isteğinde doğrudan index.html sun
app.get('/', (req, res) => {
    res.sendFile(path.join(publicDir, 'index.html'));
});

// Log ve Karantina dosyalarının hazırlanması
const logDir = path.join(__dirname, 'logs');
const logFilePath = path.join(logDir, 'analysis_history.json');
const quarantineFilePath = path.join(logDir, 'quarantine_ips.json');
const batchMetaFilePath = path.join(logDir, 'last_batch_meta.json');

if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });
if (!fs.existsSync(logFilePath)) fs.writeFileSync(logFilePath, '[]', 'utf8');
if (!fs.existsSync(quarantineFilePath)) fs.writeFileSync(quarantineFilePath, '[]', 'utf8');

// Hafızada son toplu analiz dağılımı (Dağılım Kayması / Drift hesaplaması için)
let previousBatchDistribution = null;

// Son toplu analiz veri kalitesi ve tekrarlanabilirlik metadatası
let lastBatchQualityInfo = null;
try {
    if (fs.existsSync(batchMetaFilePath)) {
        lastBatchQualityInfo = JSON.parse(fs.readFileSync(batchMetaFilePath, 'utf8'));
    }
} catch {
    lastBatchQualityInfo = null;
}

function readJsonSafe(filePath) {
    try {
        const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        return Array.isArray(parsed) ? parsed : [];
    } catch {
        return [];
    }
}

function writeJsonSafe(filePath, data, limit = 1000) {
    fs.writeFileSync(filePath, JSON.stringify(data.slice(0, limit), null, 2), 'utf8');
}

/**
 * RFC 1918 / Yerel Ağ IP Tespiti
 */
function isPrivateIp(ip = '') {
    const clean = String(ip).trim();
    if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(clean)) return true;
    if (/^192\.168\.\d{1,3}\.\d{1,3}$/.test(clean)) return true;
    if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(clean)) return true;
    const m = clean.match(/^172\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/);
    return m ? Number(m[1]) >= 16 && Number(m[1]) <= 31 : false;
}

function parseBool(val) {
    if (typeof val === 'boolean') return val;
    if (typeof val === 'number') return val === 1;
    const s = String(val || '').trim().toLowerCase();
    return ['true', '1', 'evet', 'yes'].includes(s);
}

const SCHEMA_ALIASES = {
    sourceIp: [
        'sourceIp', 'sourceip', 'kaynak_ip', 'kaynakip', 'kaynak_IP', 'source_ip', 'srcip', 'src_ip',
        'source ip', 'src ip', 'ipv4_src_addr', 'id.orig_h', 'ip', 'host', 'source'
    ],
    packetSize: [
        'packetSize', 'packetsize', 'paket_boyutu', 'paketboyutu', 'total_length_of_fwd_packets', 'total_length_of_bwd_packets',
        'fwd_packet_length_mean', 'fwd_packet_length_max', 'packet_length_mean', 'average_packet_size',
        'subflow_fwd_bytes', 'sbytes', 'dbytes', 'smean', 'dmean', 'orig_bytes', 'resp_bytes',
        'src_bytes', 'dst_bytes', 'packet_size', 'length', 'bytes', 'size', 'paket'
    ],
    duration: [
        'duration', 'sure', 'süre', 'baglanti_suresi', 'flow_duration', 'dur', 'conn_duration', 'time'
    ],
    isKnownPort: [
        'isKnownPort', 'isknownport', 'bilinen_port', 'bilinenport', 'is_known_port', 'port', 'destination_port', 'dst_port',
        'dsport', 'id.resp_p', 'dest_port', 'service', 'dport', 'dest_port_num'
    ],
    failedLogins: [
        'failedLogins', 'failedlogins', 'hatali_giris', 'hataligiris', 'hatalı_giriş', 'failed_logins',
        'num_failed_logins', 'is_ftp_login', 'syn_flag_count', 'rst_flag_count', 'failed_attempts', 'error_count'
    ],
    requestRate: [
        'requestRate', 'requestrate', 'istek_hizi', 'istekhizi', 'istek_hızı', 'flow_packets/s', 'flow_bytes/s', 'fwd_packets/s',
        'rate', 'sload', 'orig_ip_bytes', 'request_rate', 'hiz', 'hız', 'count'
    ],
    actualLabel: [
        'actualLabel', 'actuallabel', 'gercek_etiket', 'gerceketiket', 'gerçek_etiket', 'actual_label',
        'label', 'attack_cat', 'attack', 'type', 'class', 'classification', 'etiket'
    ]
};

function normalizeThresholds(raw = {}) {
    return {
        packetThreshold: Number(raw.packetThreshold) > 0 ? Number(raw.packetThreshold) : 1500,
        failedLoginThreshold: Number(raw.failedLoginThreshold) >= 0 ? Math.floor(Number(raw.failedLoginThreshold)) : 3,
        requestRateThreshold: Number(raw.requestRateThreshold) > 0 ? Number(raw.requestRateThreshold) : 80
    };
}

function normalizeInput(raw = {}) {
    const rawLowerMap = {};
    for (const [k, v] of Object.entries(raw || {})) {
        if (v !== undefined && v !== null && String(v).trim() !== '') {
            const lk = k.toLowerCase();
            rawLowerMap[lk] = v;
            rawLowerMap[lk.replace(/[^a-z0-9]/g, '')] = v;
        }
    }

    const getVal = (aliases) => {
        for (const k of aliases) {
            if (raw[k] !== undefined && raw[k] !== null && String(raw[k]).trim() !== '') return raw[k];
            const lk = k.toLowerCase();
            if (rawLowerMap[lk] !== undefined) return rawLowerMap[lk];
            const cleanK = lk.replace(/[^a-z0-9]/g, '');
            if (rawLowerMap[cleanK] !== undefined) return rawLowerMap[cleanK];
        }
        return undefined;
    };

    const sourceIpVal = getVal(SCHEMA_ALIASES.sourceIp);
    const sourceIp = String(sourceIpVal || '192.168.1.24').trim();

    const packetSizeVal = getVal(SCHEMA_ALIASES.packetSize);
    const packetSize = Math.max(0, Number(packetSizeVal) || 0);

    const durationVal = getVal(SCHEMA_ALIASES.duration);
    let duration = 0;
    if (durationVal !== undefined && durationVal !== null) {
        const rawDur = Number(durationVal);
        if (!isNaN(rawDur)) {
            // CIC-IDS2017 gibi mikro-saniye cinsinden büyük değerleri saniyeye dönüştür
            duration = rawDur > 10000 ? Number((rawDur / 1000000).toFixed(4)) : Math.max(0, rawDur);
        }
    }

    const isKnownPortVal = getVal(SCHEMA_ALIASES.isKnownPort);
    let isKnownPort = false;
    if (isKnownPortVal !== undefined && isKnownPortVal !== null) {
        const portStr = String(isKnownPortVal).trim().toLowerCase();
        if (['true', '1', 'evet', 'yes', 'standart'].includes(portStr)) {
            isKnownPort = true;
        } else if (['false', '0', 'hayir', 'no', 'bilinmeyen'].includes(portStr)) {
            isKnownPort = false;
        } else {
            const pNum = Number(isKnownPortVal);
            if (!isNaN(pNum) && pNum > 0) {
                // Standart/tanınmış port kontrolü (<= 1024 veya yaygın servis portları)
                isKnownPort = (pNum <= 1024 || [80, 443, 22, 53, 21, 25, 8080, 8443, 3389, 110, 143].includes(pNum));
            } else {
                isKnownPort = false;
            }
        }
    }

    const failedLoginsVal = getVal(SCHEMA_ALIASES.failedLogins);
    const failedLogins = Math.max(0, Math.floor(Number(failedLoginsVal) || 0));

    const requestRateVal = getVal(SCHEMA_ALIASES.requestRate);
    const requestRate = Math.max(0, Number(requestRateVal) || 10);

    const actualLabelVal = getVal(SCHEMA_ALIASES.actualLabel);
    const actualLabel = actualLabelVal ? String(actualLabelVal).trim() : null;

    const isPrivate = isPrivateIp(sourceIp);

    return {
        sourceIp,
        isPrivate,
        ipScope: isPrivate ? 'Yerel Ağ (Özel IP - RFC 1918)' : 'Dış Ağ (Genel IP)',
        packetSize,
        duration,
        isKnownPort,
        failedLogins,
        requestRate,
        actualLabel
    };
}

function detectSchemaMapping(headers = []) {
    const headerStr = headers.join(' ').toLowerCase();
    let datasetName = 'Standart Şema';

    if (headerStr.includes('total_length_of_fwd_packets') || headerStr.includes('flow_duration') || headerStr.includes('flow_packets/s')) {
        datasetName = 'CIC-IDS2017 / 2018';
    } else if (headerStr.includes('sbytes') || headerStr.includes('dur') || headerStr.includes('attack_cat')) {
        datasetName = 'UNSW-NB15';
    } else if (headerStr.includes('orig_bytes') || headerStr.includes('id.orig_h') || headerStr.includes('id.resp_p')) {
        datasetName = 'TON_IoT';
    } else if (headerStr.includes('src_bytes') || headerStr.includes('num_failed_logins')) {
        datasetName = 'NSL-KDD';
    } else if (headerStr.includes('kaynak_ip') || headerStr.includes('paket_boyutu')) {
        datasetName = 'Standart Türkçe Şema';
    } else {
        datasetName = 'Esnek Ağ Trafiği Şeması';
    }

    const mappings = [];
    const checkAndPush = (canonical, aliases) => {
        const found = headers.find(h => aliases.includes(h));
        if (found) {
            mappings.push(`${found} -> ${canonical}`);
        }
    };

    checkAndPush('Kaynak IP', SCHEMA_ALIASES.sourceIp);
    checkAndPush('Paket Boyutu', SCHEMA_ALIASES.packetSize);
    checkAndPush('Süre', SCHEMA_ALIASES.duration);
    checkAndPush('Port Türü', SCHEMA_ALIASES.isKnownPort);
    checkAndPush('Hatalı Giriş', SCHEMA_ALIASES.failedLogins);
    checkAndPush('İstek Hızı', SCHEMA_ALIASES.requestRate);
    checkAndPush('Gerçek Etiket', SCHEMA_ALIASES.actualLabel);

    const summaryText = mappings.length > 0
        ? `Şema Eşleme: ${datasetName} (${mappings.slice(0, 4).join(', ')}${mappings.length > 4 ? '...' : ''})`
        : `Şema Eşleme: ${datasetName} (Standart parametreler uygulandı)`;

    return {
        datasetName,
        mappedCount: mappings.length,
        summaryText,
        mappedColumns: mappings
    };
}

/**
 * Dinamik Özellik Katkı Analizi (Feature Attribution)
 */
function calculateFeatureAttribution(attackType, data = {}, t = {}) {
    const pkt = Math.max(0, Number(data.packetSize) || 0);
    const dur = Math.max(0, Number(data.duration) || 0);
    const fail = Math.max(0, Math.floor(Number(data.failedLogins) || 0));
    const rate = Math.max(0, Number(data.requestRate) || 0);
    const known = Boolean(data.isKnownPort);

    const pktThreshold = Number(t.packetThreshold) > 0 ? Number(t.packetThreshold) : 1500;
    const failThreshold = Number(t.failedLoginThreshold) >= 0 ? Number(t.failedLoginThreshold) : 3;
    const rateThreshold = Number(t.requestRateThreshold) > 0 ? Number(t.requestRateThreshold) : 80;

    let rawWeights = {
        istek_hizi: 10,
        paket_boyutu: 10,
        hatali_giris: 10,
        sure: 10,
        bilinen_port: 10
    };

    switch (attackType) {
        case 'DDoS / Flood Saldırısı':
            rawWeights.istek_hizi = 40 + Math.min(25, (rate / rateThreshold) * 15);
            rawWeights.paket_boyutu = 24 + Math.min(16, (pkt / pktThreshold) * 10);
            rawWeights.sure = dur < 0.5 ? 16 + (0.5 - dur) * 10 : 8;
            rawWeights.bilinen_port = known ? 8 : 12;
            rawWeights.hatali_giris = 4;
            break;
        case 'Şüpheli Yüksek Hızlı Paket Akışı':
            rawWeights.paket_boyutu = 36 + Math.min(16, (pkt / pktThreshold) * 10);
            rawWeights.sure = 26;
            rawWeights.istek_hizi = 20 + Math.min(15, (rate / rateThreshold) * 10);
            rawWeights.bilinen_port = 10;
            rawWeights.hatali_giris = 6;
            break;
        case 'Veri Sızdırma / Şüpheli Transfer':
        case 'Veri Sızdırma / Şüpheli Büyük Transfer':
            rawWeights.paket_boyutu = 44 + Math.min(20, (pkt / pktThreshold) * 10);
            rawWeights.bilinen_port = known ? 15 : 32;
            rawWeights.sure = 14;
            rawWeights.istek_hizi = 6;
            rawWeights.hatali_giris = 4;
            break;
        case 'Büyük Veri Transferi (Yedekleme vb.)':
        case 'Büyük Veri Transferi (Yedekleme / Medya)':
            rawWeights.paket_boyutu = 44 + Math.min(16, (pkt / pktThreshold) * 10);
            rawWeights.bilinen_port = 26;
            rawWeights.sure = 16;
            rawWeights.istek_hizi = 8;
            rawWeights.hatali_giris = 6;
            break;
        case 'Kaba Kuvvet (Brute-Force) Saldırısı':
        case 'Brute-Force (Kaba Kuvvet) Saldırısı':
            rawWeights.hatali_giris = 45 + Math.min(25, (fail / Math.max(1, failThreshold)) * 10);
            rawWeights.bilinen_port = known ? 15 : 28;
            rawWeights.istek_hizi = 12;
            rawWeights.sure = 8;
            rawWeights.paket_boyutu = 5;
            break;
        case 'Port Taraması ve Keşif Aktivitesi':
        case 'Port Taraması / Keşif':
            rawWeights.sure = dur < 0.2 ? 36 + (0.2 - dur) * 30 : 25;
            rawWeights.paket_boyutu = pkt < 200 ? 30 + ((200 - pkt) / 200) * 15 : 20;
            rawWeights.bilinen_port = known ? 10 : 26;
            rawWeights.istek_hizi = 10;
            rawWeights.hatali_giris = 4;
            break;
        case 'Kimlik Doğrulama Anomalisi':
        case 'Kimlik Doğrulama Anomalisi / Brute-Force':
            rawWeights.hatali_giris = 50 + Math.min(20, (fail / Math.max(1, failThreshold)) * 10);
            rawWeights.bilinen_port = 18;
            rawWeights.istek_hizi = 14;
            rawWeights.sure = 10;
            rawWeights.paket_boyutu = 8;
            break;
        default: // Normal Trafik veya Karantina
            rawWeights.istek_hizi = 20 + Math.min(15, (rate / rateThreshold) * 10);
            rawWeights.paket_boyutu = 20 + Math.min(15, (pkt / pktThreshold) * 10);
            rawWeights.hatali_giris = 18 + Math.min(15, (fail / Math.max(1, failThreshold)) * 10);
            rawWeights.bilinen_port = known ? 18 : 22;
            rawWeights.sure = 16;
            break;
    }

    const total = Object.values(rawWeights).reduce((a, b) => a + b, 0) || 1;
    const meta = {
        istek_hizi: { label: 'İstek Hızı (req/s)', value: `${rate} req/s` },
        paket_boyutu: { label: 'Paket Boyutu (Byte)', value: `${pkt} B` },
        hatali_giris: { label: 'Hatalı Giriş Sayısı', value: `${fail}` },
        sure: { label: 'Bağlantı Süresi (sn)', value: `${dur} sn` },
        bilinen_port: { label: 'Port Türü', value: known ? 'Standart Port' : 'Bilinmeyen Port' }
    };

    return Object.entries(rawWeights)
        .map(([feature, weight]) => ({
            feature,
            label: meta[feature].label,
            value: meta[feature].value,
            weight: Number(((weight / total) * 100).toFixed(1))
        }))
        .sort((a, b) => b.weight - a.weight);
}

/**
 * Karşı-Olgusal Analiz (Counterfactual Explanation - Sparsity & Cost)
 * Normal sınıfa geçiş için gereken minimal parametre değişimini,
 * değişen özellik adedini (Sparsity) ve normalize mesafeyi (Cost) hesaplar.
 */
function calculateCounterfactuals(attackType, data, t) {
    const isNormal = attackType === 'Normal Trafik';
    const changes = [];
    let targetClass = 'Normal Trafik';
    let explanation = '';

    if (isNormal) {
        // Zaten Normal sınıfında ise en yakın saldırı sınırını hesapla
        targetClass = 'DDoS / Flood Saldırısı';
        const neededPacketDelta = Math.max(1, (t.packetThreshold + 10) - data.packetSize);
        const costVal = Number((neededPacketDelta / 5000).toFixed(2));
        changes.push({
            feature: 'paket_boyutu',
            label: 'Paket Boyutu',
            from: `${data.packetSize} B`,
            to: `${t.packetThreshold + 10} B`,
            delta: `+${neededPacketDelta} B`
        });
        explanation = `Mevcut akış zaten "Normal Trafik" profilindedir. Karşı-olgusal sınır analizi: Paket boyutu +${neededPacketDelta} B artırılır ve bağlantı süresi < 0.5 sn olursa akış doğrudan saldırı sınıfına geçer.`;

        return {
            isAlreadyNormal: true,
            targetClass,
            sparsity: 1,
            cost: costVal,
            changes,
            explanation
        };
    }

    // Saldırı sınıflarında "Normal Trafik" sınıfına dönüş için gereken en küçük müdahale
    switch (attackType) {
        case 'DDoS / Flood Saldırısı':
        case 'Şüpheli Yüksek Hızlı Paket Akışı': {
            const targetPacket = Math.min(data.packetSize, t.packetThreshold - 50);
            const deltaPkt = data.packetSize - targetPacket;
            changes.push({
                feature: 'paket_boyutu',
                label: 'Paket Boyutu',
                from: `${data.packetSize} B`,
                to: `${targetPacket} B`,
                delta: `-${deltaPkt} B`
            });
            const costVal = Number((deltaPkt / 5000).toFixed(2));
            explanation = `Normal sınıfa geçiş için en düşük maliyetli değişim: Paket Boyutu ${data.packetSize} B değerinden ${targetPacket} B seviyesine indirilmelidir. Böylece kök düğümdeki yüksek paket filtresi aşılmaz ve akış doğrudan Normal olarak değerlendirilir.`;
            return {
                isAlreadyNormal: false,
                targetClass: 'Normal Trafik',
                sparsity: 1,
                cost: costVal,
                changes,
                explanation
            };
        }
        case 'Kaba Kuvvet (Brute-Force) Saldırısı':
        case 'Kimlik Doğrulama Anomalisi': {
            const targetLogins = Math.max(0, t.failedLoginThreshold - 1);
            const deltaLogins = data.failedLogins - targetLogins;
            changes.push({
                feature: 'hatali_giris',
                label: 'Hatalı Giriş Sayısı',
                from: `${data.failedLogins}`,
                to: `${targetLogins}`,
                delta: `-${deltaLogins}`
            });
            const costVal = Number((deltaLogins / 20).toFixed(2));
            explanation = `Normal sınıfa geçiş için en düşük maliyetli değişim: Başarısız oturum açma sayısı ${data.failedLogins} seviyesinden ${targetLogins} seviyesine düşürülmelidir.`;
            return {
                isAlreadyNormal: false,
                targetClass: 'Normal Trafik',
                sparsity: 1,
                cost: costVal,
                changes,
                explanation
            };
        }
        case 'Port Taraması ve Keşif Aktivitesi': {
            // Küçük paket ve kısa süreyi normalleştirmek için süreyi veya paket boyutunu eşik üstüne çekmek
            changes.push({
                feature: 'bilinen_port',
                label: 'Port Türü',
                from: 'Bilinmeyen Port',
                to: 'Standart Port',
                delta: 'Standart servise yönlendirme'
            });
            const costVal = 0.15;
            explanation = `Normal sınıfa geçiş için en düşük maliyetli değişim: Trafik bilinmeyen portlar yerine standart/yetkili bir porta yönlendirilmelidir.`;
            return {
                isAlreadyNormal: false,
                targetClass: 'Normal Trafik',
                sparsity: 1,
                cost: costVal,
                changes,
                explanation
            };
        }
        case 'Veri Sızdırma / Şüpheli Transfer':
        case 'Büyük Veri Transferi (Yedekleme vb.)': {
            const targetPacket = Math.min(data.packetSize, t.packetThreshold - 50);
            const deltaPkt = data.packetSize - targetPacket;
            changes.push({
                feature: 'paket_boyutu',
                label: 'Paket Boyutu',
                from: `${data.packetSize} B`,
                to: `${targetPacket} B`,
                delta: `-${deltaPkt} B`
            });
            const costVal = Number((deltaPkt / 5000).toFixed(2));
            explanation = `Normal sınıfa geçiş için en düşük maliyetli değişim: Veri transfer paket boyutu ${data.packetSize} B değerinden ${targetPacket} B eşik altına indirilmelidir.`;
            return {
                isAlreadyNormal: false,
                targetClass: 'Normal Trafik',
                sparsity: 1,
                cost: costVal,
                changes,
                explanation
            };
        }
        default: {
            changes.push({
                feature: 'paket_boyutu',
                label: 'Paket Boyutu',
                from: `${data.packetSize} B`,
                to: `${t.packetThreshold} B`,
                delta: `Normalleşme eşiği`
            });
            return {
                isAlreadyNormal: false,
                targetClass: 'Normal Trafik',
                sparsity: 1,
                cost: 0.10,
                changes,
                explanation: 'Trafik parametreleri güvenlik eşik sınırlarının içine çekilmelidir.'
            };
        }
    }
}

/**
 * Sınır Duyarlılığı ve Karar Güveni Analizi (Boundary Sensitivity & Decision Confidence)
 */
function calculateBoundarySensitivity(data, t, attackType) {
    const margins = [];

    // Paket boyutu eşiğine yakınlık
    const pktDiff = Math.abs(data.packetSize - t.packetThreshold);
    const pktMargin = pktDiff / t.packetThreshold;
    margins.push({
        feature: 'Paket Boyutu',
        actual: `${data.packetSize} B`,
        threshold: `${t.packetThreshold} B`,
        margin: pktMargin
    });

    // İstek hızı eşiğine yakınlık (özellikle DDoS ve yüksek akışlarda)
    if (attackType.includes('DDoS') || attackType.includes('Akış')) {
        const rateDiff = Math.abs(data.requestRate - t.requestRateThreshold);
        const rateMargin = rateDiff / t.requestRateThreshold;
        margins.push({
            feature: 'İstek Hızı',
            actual: `${data.requestRate} req/s`,
            threshold: `${t.requestRateThreshold} req/s`,
            margin: rateMargin
        });
    }

    // Hatalı giriş eşiğine yakınlık
    if (attackType.includes('Kuvvet') || attackType.includes('Kimlik') || data.failedLogins > 0) {
        const failDiff = Math.abs(data.failedLogins - t.failedLoginThreshold);
        const failMargin = failDiff / Math.max(1, t.failedLoginThreshold);
        margins.push({
            feature: 'Hatalı Giriş Sayısı',
            actual: `${data.failedLogins}`,
            threshold: `${t.failedLoginThreshold}`,
            margin: failMargin
        });
    }

    // En kritik ve eşiğe en yakın parametreyi bul
    margins.sort((a, b) => a.margin - b.margin);
    const critical = margins[0] || {
        feature: 'Paket Boyutu',
        actual: `${data.packetSize} B`,
        threshold: `${t.packetThreshold} B`,
        margin: 0.4
    };

    const marginPercentage = Number((critical.margin * 100).toFixed(1));
    let sensitivityLevel = 'Düşük (Kararlı)';
    let isBoundaryDecision = false;
    let message = '';
    let confidence = 94;

    if (critical.margin <= 0.12) {
        sensitivityLevel = 'Yüksek (Sınır Kararı)';
        isBoundaryDecision = true;
        confidence = Math.max(72, Math.min(84, Math.round(72 + critical.margin * 100)));
        message = `Kritik parametre (${critical.feature}), karar eşiğine çok yakın (%${marginPercentage} mesafe). Ağdaki küçük dalgalanmalar sınıflandırma kararını değiştirebilir.`;
    } else if (critical.margin <= 0.30) {
        sensitivityLevel = 'Orta (Dengeli)';
        isBoundaryDecision = false;
        confidence = Math.min(92, Math.round(84 + critical.margin * 25));
        message = `Parametreler karar eşiğine orta düzeyde (%${marginPercentage}) mesafededir. Karar istikrarlı görünmektedir.`;
    } else {
        sensitivityLevel = 'Düşük (Kararlı)';
        isBoundaryDecision = false;
        confidence = Math.min(99, Math.round(92 + Math.min(7, (critical.margin - 0.30) * 10)));
        message = `Parametreler karar eşik sınırlarından belirgin biçimde uzaktadır (%${marginPercentage} mesafe). Yüksek karar güveni ve kararlılık tespit edildi.`;
    }

    return {
        sensitivityLevel,
        isBoundaryDecision,
        marginPercentage,
        criticalFeature: critical.feature,
        criticalThreshold: critical.threshold,
        actualValue: critical.actual,
        confidence,
        message
    };
}

/**
 * SOC Müdahale Rehberi (Playbook) ve Ağ İzolasyon Adımları
 */
function getSocPlaybook(attackType, data) {
    const isPrivate = data.isPrivate;
    const ip = data.sourceIp;

    let steps = [];
    let title = '';

    switch (attackType) {
        case 'DDoS / Flood Saldırısı':
            title = 'DDoS ve Trafik Boğma Müdahale Prosedürü';
            steps = [
                'Uç Güvenlik Duvarında (Border Firewall / WAF) SYN/UDP paket hız sınırlaması (rate-limiting) devreye alın.',
                `Kaynak IP (${ip}) adresini sınır yönlendirici (BGP/ACL) üzerinde drop kuralına bağlayarak karantinaya alın.`,
                'Hizmet reddi devam ediyorsa CDN / Cloud DDoS temizleme merkezine trafiği offload edin.'
            ];
            break;
        case 'Kaba Kuvvet (Brute-Force) Saldırısı':
            title = 'Kimlik Denetimi ve Kaba Kuvvet Müdahale Prosedürü';
            steps = [
                `Hedef servisteki (SSH / RDP / Web Login) oturum açma denemelerini ${ip} için geçici olarak bloke edin.`,
                'Hedef kullanıcı hesaplarında parola sıfırlama zorunluluğu getirin ve Çok Faktörlü Doğrulamayı (MFA) aktifleştirin.',
                'Active Directory / PAM günlüklerinde başarılı yetkisiz oturum oluşup oluşmadığını denetleyin.'
            ];
            break;
        case 'Port Taraması ve Keşif Aktivitesi':
            title = 'Port Taraması ve Ağ Keşfi Müdahale Prosedürü';
            steps = [
                'Ağ IDS/IPS sensörlerinde port tarama tespit kuralını uyarı modundan dinamik engelleme moduna alın.',
                'Dış ağa açık gereksiz portları kapatın; yönetim arayüzlerini yalnızca VPN ardına çekin.',
                `Tarama yapan ${ip} adresini 24 saatlik geçici engelleme listesine kaydedin.`
            ];
            break;
        case 'Veri Sızdırma / Şüpheli Transfer':
            title = 'Veri Sızıntısı ve Şüpheli Dışa Aktarım Müdahale Prosedürü';
            steps = [
                `Bilinmeyen port üzerinden gerçekleşen giden (egress) bağlantıyı güvenlik duvarından derhal sonlandırın.`,
                'DLP (Veri Kaybı Önleme) alarmlarını inceleyerek dışarıya aktarılan dosya hash ve türlerini tespit edin.',
                `İlgili iç uç noktayı (${ip}) ağdan izole ederek adli bilişim (forensics) incelemesi başlatın.`
            ];
            break;
        case 'Şüpheli Yüksek Hızlı Paket Akışı':
            title = 'Yüksek Hızlı Akış İzleme ve Önleme Prosedürü';
            steps = [
                'Akışın geçici bir burst mü yoksa veri transferi mi olduğunu NetFlow/sFlow üzerinden doğrulayın.',
                'Bant genişliği doygunluğunu önlemek için ilgili IP için QoS hız kısıtı uygulayın.'
            ];
            break;
        default:
            title = 'Standart Ağ Trafiği Güvenlik Prosedürü';
            steps = [
                'Trafik profili normal sınırlar dahilindedir. Standart SIEM korelasyonu ve izleme aktiftir.',
                'Herhangi bir aktif müdahale veya blokaj işlemi gerekmemektedir.'
            ];
            break;
    }

    let privateWarning = null;
    if (isPrivate) {
        privateWarning = `İç Ağ IP Uyarısı: ${ip} adresi yerel ağa (RFC 1918) aittir. Karantina veya blokaj uygularken kritik iç servislerin kesintiye uğramayacağını teyit edin.`;
    }

    return {
        title,
        steps,
        isPrivate,
        privateWarning
    };
}

/**
 * Açıklanabilir Karar Ağacı (XAI) Sınıflandırma ve Çıkarım Motoru
 */
function classifyTraffic(rawData, rawThresholds = {}) {
    const data = normalizeInput(rawData);
    const t = normalizeThresholds(rawThresholds);
    const quarantineList = readJsonSafe(quarantineFilePath);
    const quarantineItem = quarantineList.find(item => item.ip === data.sourceIp);
    const isQuarantined = Boolean(quarantineItem);

    const decisionPath = [];

    let attackType = 'Normal Trafik';
    let riskLevel = 'Düşük';
    let riskScore = 10;
    let recommendation = 'Trafik normal ağ profiliyle uyumlu. Standart izleme yeterlidir.';

    if (isQuarantined) {
        decisionPath.push({
            node: 'ÖN KONTROL [KARANTİNA]',
            feature: 'Karantina Durumu',
            condition: 'Kaynak IP Karantina Listesinde Kayıtlı mı?',
            actualValue: 'Karantinada Kayıtlı',
            threshold: 'Karantina Listesi',
            branch: 'EVET',
            evaluation: `Kaynak IP (${data.sourceIp}) önceden güvenlik karantinasına alınmış.`
        });
    }

    // 1. KÖK DÜĞÜM (Paket Boyutu Kontrolü)
    const isPktHigh = data.packetSize > t.packetThreshold;
    decisionPath.push({
        node: 'KÖK DÜĞÜM',
        feature: 'Paket Boyutu',
        condition: `Paket Boyutu > ${t.packetThreshold} B?`,
        actualValue: `${data.packetSize} B`,
        threshold: `${t.packetThreshold} B`,
        branch: isPktHigh ? 'EVET' : 'HAYIR',
        evaluation: isPktHigh ? 'Büyük boyutlu paket akışı dalına yönelindi.' : 'Standart boyutlu paket akışı dalına yönelindi.'
    });

    if (isPktHigh) {
        // DÜĞÜM 1A (Bağlantı Süresi Kontrolü)
        const isDurationShort = data.duration < 0.5;
        decisionPath.push({
            node: 'DÜĞÜM 1A',
            feature: 'Bağlantı Süresi',
            condition: 'Bağlantı Süresi < 0.5 sn?',
            actualValue: `${data.duration} sn`,
            threshold: '0.5 sn',
            branch: isDurationShort ? 'EVET' : 'HAYIR',
            evaluation: isDurationShort ? 'Kısa süreli anlık yüksek akış dalına yönelindi.' : 'Uzun süreli sürekli transfer dalına yönelindi.'
        });

        if (isDurationShort) {
            // DÜĞÜM 2A (İstek Hızı Kontrolü)
            const isRateHigh = data.requestRate >= t.requestRateThreshold;
            decisionPath.push({
                node: 'DÜĞÜM 2A',
                feature: 'İstek Hızı',
                condition: `İstek Hızı >= ${t.requestRateThreshold} req/s?`,
                actualValue: `${data.requestRate} req/s`,
                threshold: `${t.requestRateThreshold} req/s`,
                branch: isRateHigh ? 'EVET' : 'HAYIR',
                evaluation: isRateHigh ? 'Aşırı yüksek istek hızı tespit edildi (DDoS / Flood).' : 'İstek hızı eşiğin altında kaldı.'
            });

            if (isRateHigh) {
                attackType = 'DDoS / Flood Saldırısı';
                riskLevel = 'Yüksek';
                riskScore = 96;
                recommendation = 'WAF ve Güvenlik Duvarında IP hız sınırı uygulayın; kaynak IP adresini karantinaya alın.';
            } else {
                attackType = 'Şüpheli Yüksek Hızlı Paket Akışı';
                riskLevel = 'Orta';
                riskScore = 68;
                recommendation = 'Kısa süreli yüksek boyutlu paket kaynağını doğrulayın ve anlık trafik artışını izleyin.';
            }
        } else {
            // DÜĞÜM 2B (Port Türü Kontrolü)
            const isKnown = data.isKnownPort;
            decisionPath.push({
                node: 'DÜĞÜM 2B',
                feature: 'Port Türü',
                condition: 'Standart / Bilinen Port Kullanımı mı?',
                actualValue: isKnown ? 'Standart Port' : 'Bilinmeyen Port',
                threshold: 'Standart Port',
                branch: isKnown ? 'EVET' : 'HAYIR',
                evaluation: isKnown ? 'Standart port üzerinden meşru büyük transfer (Yedekleme vb.).' : 'Bilinmeyen port üzerinden yetkisiz büyük transfer (Veri Sızdırma).'
            });

            if (!isKnown) {
                attackType = 'Veri Sızdırma / Şüpheli Transfer';
                riskLevel = 'Yüksek';
                riskScore = 89;
                recommendation = 'Veri kaybı önleme (DLP) denetimi başlatın ve bilinmeyen port çıkışını kısıtlayın.';
            } else {
                attackType = 'Büyük Veri Transferi (Yedekleme vb.)';
                riskLevel = 'Orta';
                riskScore = 45;
                recommendation = 'Planlı yedekleme saatleriyle karşılaştırın; mesai dışı ise oturumu inceleyin.';
            }
        }
    } else {
        // Küçük/Standart Paket Boyutu Dalları
        if (!data.isKnownPort && data.failedLogins > t.failedLoginThreshold) {
            decisionPath.push({
                node: 'DÜĞÜM 1B',
                feature: 'Port ve Hatalı Giriş',
                condition: `Bilinmeyen Port VE Hatalı Giriş > ${t.failedLoginThreshold}?`,
                actualValue: `Bilinmeyen Port, ${data.failedLogins} Hatalı Giriş`,
                threshold: `> ${t.failedLoginThreshold}`,
                branch: 'EVET',
                evaluation: 'Yetkisiz portta tekrarlayan başarısız kimlik doğrulama denemeleri.'
            });
            attackType = 'Kaba Kuvvet (Brute-Force) Saldırısı';
            riskLevel = 'Yüksek';
            riskScore = 93;
            recommendation = 'Hesap kilitleme ve iki adımlı doğrulamayı (MFA) devreye alın, saldırgan IP adresini karantinaya ekleyin.';
        } else if (!data.isKnownPort && data.duration < 0.2 && data.packetSize < 200) {
            decisionPath.push({
                node: 'DÜĞÜM 1C',
                feature: 'Port Keşif İmzası',
                condition: `Bilinmeyen Port + Paket < 200 B + Süre < 0.2 sn?`,
                actualValue: `${data.packetSize} B, ${data.duration} sn, Bilinmeyen Port`,
                threshold: '< 200 B, < 0.2 sn',
                branch: 'EVET',
                evaluation: 'Kısa süreli küçük paketlerle gerçekleştirilen port yoklama davranışı.'
            });
            attackType = 'Port Taraması ve Keşif Aktivitesi';
            riskLevel = 'Orta';
            riskScore = 74;
            recommendation = 'Güvenlik duvarı port tarama korumasını sıkılaştırın ve tarama yapan IP adresini izlemeye alın.';
        } else if (data.failedLogins > t.failedLoginThreshold) {
            decisionPath.push({
                node: 'DÜĞÜM 1D',
                feature: 'Standart Port Hatalı Giriş',
                condition: `Standart Portta Hatalı Giriş > ${t.failedLoginThreshold}?`,
                actualValue: `${data.failedLogins} Hatalı Giriş`,
                threshold: `> ${t.failedLoginThreshold}`,
                branch: 'EVET',
                evaluation: 'Standart servis üzerinde başarısız giriş anomalisi.'
            });
            attackType = 'Kimlik Doğrulama Anomalisi';
            riskLevel = 'Orta';
            riskScore = 69;
            recommendation = 'Oturum açma loglarını inceleyin ve tekrarlayan hatalı girişlere hız sınırı uygulayın.';
        } else {
            decisionPath.push({
                node: 'DÜĞÜM 1E',
                feature: 'Genel Eşik Kontrolü',
                condition: 'Tüm güvenlik parametreleri normal sınırlar dahilinde mi?',
                actualValue: 'Güvenli Değerler',
                threshold: 'Normal Aralık',
                branch: 'EVET',
                evaluation: 'Ağ parametreleri standart profil ile tam uyumlu.'
            });
        }
    }

    if (isQuarantined) {
        riskScore = Math.min(100, riskScore + 5);
        if (riskLevel === 'Düşük') riskLevel = 'Orta';
        recommendation = `[KARANTİNA UYARISI] ${data.sourceIp} karantina listesinde kayıtlı! ${recommendation}`;
    }

    const featureAttribution = calculateFeatureAttribution(attackType, data, t);
    const counterfactuals = calculateCounterfactuals(attackType, data, t);
    const boundarySensitivity = calculateBoundarySensitivity(data, t, attackType);
    const socPlaybook = getSocPlaybook(attackType, data);

    return {
        input: data,
        thresholds: t,
        isQuarantined,
        attackType,
        riskLevel,
        riskScore,
        confidence: boundarySensitivity.confidence,
        recommendation,
        decisionPath,
        featureAttribution,
        counterfactuals,
        boundarySensitivity,
        socPlaybook
    };
}

function saveLog(source, input, result) {
    const logs = readJsonSafe(logFilePath);
    logs.unshift({
        id: `${Date.now()}-${Math.floor(Math.random() * 10000)}`,
        timestamp: new Date().toISOString(),
        source,
        input,
        output: {
            attackType: result.attackType,
            riskLevel: result.riskLevel,
            riskScore: result.riskScore,
            confidence: result.confidence,
            recommendation: result.recommendation,
            decisionPath: result.decisionPath,
            counterfactuals: result.counterfactuals,
            boundarySensitivity: result.boundarySensitivity
        }
    });
    writeJsonSafe(logFilePath, logs, 1000);
}

// API Rotaları
app.post('/api/analyze', (req, res) => {
    const { thresholds, ...payload } = req.body || {};
    const result = classifyTraffic(payload, thresholds);
    saveLog('Manuel Analiz', result.input, result);
    res.json(result);
});

function normalizeHeaderName(header = '') {
    return String(header || '')
        .trim()
        .replace(/İ/g, 'i')
        .replace(/I/g, 'i')
        .toLowerCase()
        .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
        .replace(/ı/g, 'i')
        .replace(/ğ/g, 'g')
        .replace(/ü/g, 'u')
        .replace(/ş/g, 's')
        .replace(/ö/g, 'o')
        .replace(/ç/g, 'c')
        .replace(/[\s\-_]+/g, '_');
}

/**
 * Toplu CSV Analizi ve Akademik Değerlendirme
 */
app.post('/api/analyze-csv', (req, res) => {
    const { csvContent, thresholds } = req.body || {};
    if (!csvContent || !String(csvContent).trim()) {
        return res.status(400).json({ error: 'Geçerli bir CSV içeriği gönderilmedi.' });
    }

    const normalizedCsv = String(csvContent).replace(/\r\n/g, '\n');
    const rawLines = normalizedCsv.split('\n');
    // Son satır boş bırakılmışsa (standart dosya sonu \n) hariç tut
    if (rawLines.length > 1 && rawLines[rawLines.length - 1].trim() === '') {
        rawLines.pop();
    }
    const totalLinesRead = Math.max(0, rawLines.length - 1); // Başlık satırı hariç toplam veri satırı

    // Şema ve sütun eşleme tespiti
    const headerLine = rawLines[0] || '';
    const headerTokens = headerLine.split(/[,;\t]/).map(h => normalizeHeaderName(h.trim()));
    const schemaMapping = detectSchemaMapping(headerTokens);

    const results = [];

    Readable.from([normalizedCsv])
        .pipe(csv({ mapHeaders: ({ header }) => normalizeHeaderName(header) }))
        .on('data', row => {
            const hasData = Object.values(row).some(v => String(v || '').trim() !== '');
            if (!hasData) return;
            try {
                const analysis = classifyTraffic(row, thresholds);
                saveLog('CSV Toplu Analiz', analysis.input, analysis);
                results.push(analysis);
            } catch {
                // Hatalı satırı atla
            }
        })
        .on('end', () => {
            if (results.length === 0) {
                return res.status(400).json({ error: 'CSV dosyasında geçerli veri satırı bulunamadı.' });
            }

            const skippedRows = Math.max(0, totalLinesRead - results.length);

            // Sınıf Dağılımı (Class Distribution)
            const classCounts = {};
            results.forEach(r => {
                classCounts[r.attackType] = (classCounts[r.attackType] || 0) + 1;
            });
            const classDistribution = Object.entries(classCounts).map(([className, count]) => ({
                className,
                count,
                percentage: Number(((count / results.length) * 100).toFixed(1))
            })).sort((a, b) => b.count - a.count);

            // Dağılım Kayması (Data Drift) Analizi
            let driftAnalysis = null;
            if (previousBatchDistribution && previousBatchDistribution.length > 0) {
                const prevMap = {};
                previousBatchDistribution.forEach(item => {
                    prevMap[item.className] = item.percentage;
                });
                const classDrift = classDistribution.map(curr => {
                    const prevPct = prevMap[curr.className] || 0;
                    const deltaPct = Number((curr.percentage - prevPct).toFixed(1));
                    return {
                        className: curr.className,
                        currentPct: curr.percentage,
                        previousPct: prevPct,
                        deltaPct
                    };
                });
                driftAnalysis = {
                    hasPreviousBatch: true,
                    classDrift,
                    significantDriftDetected: classDrift.some(d => Math.abs(d.deltaPct) >= 10)
                };
            } else {
                driftAnalysis = {
                    hasPreviousBatch: false,
                    classDrift: classDistribution.map(c => ({
                        className: c.className,
                        currentPct: c.percentage,
                        previousPct: c.percentage,
                        deltaPct: 0
                    })),
                    significantDriftDetected: false
                };
            }
            // Güncel dağılımı referans olarak sakla
            previousBatchDistribution = classDistribution;

            // Tekrarlı Şüpheli IP Özeti (Repeated Suspicious IP Aggregation)
            const ipCounts = {};
            results.forEach(r => {
                const ip = r.input.sourceIp || 'Bilinmeyen';
                if (!ipCounts[ip]) {
                    ipCounts[ip] = {
                        ip,
                        isPrivate: r.input.isPrivate,
                        ipScope: r.input.ipScope,
                        count: 0,
                        attacks: new Set(),
                        highestRisk: 'Düşük',
                        isQuarantined: r.isQuarantined
                    };
                }
                ipCounts[ip].count++;
                ipCounts[ip].attacks.add(r.attackType);
                if (r.riskLevel === 'Yüksek') ipCounts[ip].highestRisk = 'Yüksek';
                else if (r.riskLevel === 'Orta' && ipCounts[ip].highestRisk !== 'Yüksek') ipCounts[ip].highestRisk = 'Orta';
            });

            const repeatedIps = Object.values(ipCounts)
                .filter(item => item.count >= 2 || item.highestRisk === 'Yüksek')
                .map(item => ({
                    ip: item.ip,
                    isPrivate: item.isPrivate,
                    ipScope: item.ipScope,
                    flowCount: item.count,
                    highestRisk: item.highestRisk,
                    attackTypes: Array.from(item.attacks).join(', '),
                    isQuarantined: item.isQuarantined
                }))
                .sort((a, b) => b.flowCount - a.flowCount)
                .slice(0, 15);

            // Etiketli Veri Seti Akademik Değerlendirmesi & Karışıklık Matrisi (Confusion Matrix)
            const labeled = results.filter(r => Boolean(r.input.actualLabel && String(r.input.actualLabel).trim() !== ''));
            let evaluation = null;

            if (labeled.length > 0) {
                // Etiket normalizasyonu eşleme fonksiyonu
                const normalizeLabel = (l) => {
                    const low = String(l || '').toLowerCase().trim();
                    if (low.includes('ddos') || low.includes('flood')) return 'DDoS / Flood Saldırısı';
                    if (low.includes('kaba') || low.includes('brute')) return 'Kaba Kuvvet (Brute-Force) Saldırısı';
                    if (low.includes('port') || low.includes('tara') || low.includes('kesif') || low.includes('keşif')) return 'Port Taraması ve Keşif Aktivitesi';
                    if (low.includes('sizdir') || low.includes('sızdır') || low.includes('exfil')) return 'Veri Sızdırma / Şüpheli Transfer';
                    if (low.includes('buyuk') || low.includes('büyük') || low.includes('yedek')) return 'Büyük Veri Transferi (Yedekleme vb.)';
                    if (low.includes('kimlik') || low.includes('auth')) return 'Kimlik Doğrulama Anomalisi';
                    if (low.includes('normal')) return 'Normal Trafik';
                    return l;
                };

                // Tüm benzersiz sınıfları topla
                const uniqueClassesSet = new Set();
                labeled.forEach(r => {
                    uniqueClassesSet.add(r.attackType);
                    uniqueClassesSet.add(normalizeLabel(r.input.actualLabel));
                });
                const classNames = Array.from(uniqueClassesSet);

                // Confusion Matrix başlat: matrix[actual][predicted] = count
                const matrix = {};
                classNames.forEach(a => {
                    matrix[a] = {};
                    classNames.forEach(p => {
                        matrix[a][p] = 0;
                    });
                });

                let matched = 0;
                let falseNegativesCount = 0; // Gerçekte saldırı iken Normal denilenler
                let falsePositivesCount = 0; // Gerçekte Normal iken saldırı denilenler

                labeled.forEach(r => {
                    const actualNorm = normalizeLabel(r.input.actualLabel);
                    const predNorm = r.attackType;

                    if (matrix[actualNorm] && matrix[actualNorm][predNorm] !== undefined) {
                        matrix[actualNorm][predNorm]++;
                    }

                    const isMatch = actualNorm === predNorm ||
                                  predNorm.toLowerCase().includes(actualNorm.toLowerCase()) ||
                                  actualNorm.toLowerCase().includes(predNorm.toLowerCase());

                    if (isMatch) matched++;

                    // Güvenlik kritik Yanlış Negatif / Pozitif tespiti
                    const isActualAttack = actualNorm !== 'Normal Trafik';
                    const isPredNormal = predNorm === 'Normal Trafik';

                    if (isActualAttack && isPredNormal) {
                        falseNegativesCount++;
                    } else if (!isActualAttack && !isPredNormal) {
                        falsePositivesCount++;
                    }
                });

                // Sınıf bazlı Precision, Recall, F1 hesabı
                const classMetrics = {};
                classNames.forEach(c => {
                    let tp = 0;
                    let fp = 0;
                    let fn = 0;
                    let support = 0;

                    labeled.forEach(r => {
                        const actualNorm = normalizeLabel(r.input.actualLabel);
                        const predNorm = r.attackType;

                        if (actualNorm === c) support++;
                        if (actualNorm === c && predNorm === c) tp++;
                        else if (actualNorm !== c && predNorm === c) fp++;
                        else if (actualNorm === c && predNorm !== c) fn++;
                    });

                    const prec = (tp + fp) > 0 ? (tp / (tp + fp)) : 0;
                    const rec = (tp + fn) > 0 ? (tp / (tp + fn)) : 0;
                    const f1 = (prec + rec) > 0 ? (2 * prec * rec) / (prec + rec) : 0;

                    classMetrics[c] = {
                        support,
                        precision: Number((prec * 100).toFixed(1)),
                        recall: Number((rec * 100).toFixed(1)),
                        f1: Number((f1 * 100).toFixed(1))
                    };
                });

                // Global Metrikler: Accuracy, Macro-F1, Weighted-F1
                const activeClasses = classNames.filter(c => classMetrics[c].support > 0);
                const macroPrecision = activeClasses.length > 0
                    ? Number((activeClasses.reduce((sum, c) => sum + classMetrics[c].precision, 0) / activeClasses.length).toFixed(1))
                    : 0;
                const macroRecall = activeClasses.length > 0
                    ? Number((activeClasses.reduce((sum, c) => sum + classMetrics[c].recall, 0) / activeClasses.length).toFixed(1))
                    : 0;
                const macroF1 = (macroPrecision + macroRecall) > 0
                    ? Number(((2 * macroPrecision * macroRecall) / (macroPrecision + macroRecall)).toFixed(1))
                    : 0;

                const weightedF1 = Number((activeClasses.reduce((sum, c) => sum + (classMetrics[c].f1 * classMetrics[c].support), 0) / labeled.length).toFixed(1));
                const accuracy = Number(((matched / labeled.length) * 100).toFixed(1));

                evaluation = {
                    labeledCount: labeled.length,
                    matchedCount: matched,
                    accuracy,
                    macroPrecision,
                    macroRecall,
                    macroF1,
                    weightedF1,
                    precision: macroPrecision,
                    recall: macroRecall,
                    f1Score: macroF1,
                    f1: macroF1,
                    classMetrics,
                    confusionMatrix: {
                        classes: classNames,
                        matrix
                    },
                    securitySummary: {
                        falseNegatives: falseNegativesCount,
                        falsePositives: falsePositivesCount,
                        fnRate: Number(((falseNegativesCount / labeled.length) * 100).toFixed(1)),
                        fpRate: Number(((falsePositivesCount / labeled.length) * 100).toFixed(1)),
                        criticalWarning: falseNegativesCount > 0
                            ? `${falseNegativesCount} adet saldırı akışı "Normal Trafik" olarak sınıflandırılarak kaçırılmıştır (Yanlış Negatif). Güvenlik eşiklerini sıkılaştırmayı değerlendirin.`
                            : 'Mükemmel tespit: Etiketli veri setinde kaçırılan saldırı akışı (Yanlış Negatif = 0) tespit edilmedi.'
                    }
                };
            }

            let driftSummaryText = '';
            if (driftAnalysis.hasPreviousBatch) {
                const nonZeroShifts = driftAnalysis.classDrift
                    .filter(d => d.deltaPct !== 0)
                    .map(d => `${d.className} (${d.deltaPct > 0 ? '+' : ''}${d.deltaPct}%)`);
                driftSummaryText = nonZeroShifts.length > 0
                    ? `Dağılım Farkı: ${nonZeroShifts.join(', ')} (Önceki toplu analize kıyasla)`
                    : 'Dağılım Farkı: Önceki toplu analize göre sınıf oranları sabit seyrediyor.';
            } else {
                driftSummaryText = 'Dağılım Referansı: İlk toplu analiz referans baz dağılım olarak kaydedildi.';
            }

            // Tekrarlanabilirlik ve Veri Kalitesi Metadatası Kaydı
            lastBatchQualityInfo = {
                totalLinesRead,
                validRowsProcessed: results.length,
                skippedRowsCount: skippedRows,
                datasetName: schemaMapping.datasetName || 'Standart Veri Seti',
                schemaMappingSummary: schemaMapping.summaryText || 'Standart Sütun Eşlemesi',
                lastAnalyzedAt: new Date().toISOString()
            };
            try {
                fs.writeFileSync(batchMetaFilePath, JSON.stringify(lastBatchQualityInfo, null, 2), 'utf8');
            } catch (err) {
                // Hata durumunda sessizce devam et
            }

            res.json({
                summary: {
                    total: results.length,
                    highRisk: results.filter(r => r.riskLevel === 'Yüksek').length,
                    mediumRisk: results.filter(r => r.riskLevel === 'Orta').length,
                    lowRisk: results.filter(r => r.riskLevel === 'Düşük').length
                },
                dataQuality: {
                    totalLinesRead,
                    validRowsProcessed: results.length,
                    skippedRowsCount: skippedRows,
                    isClean: skippedRows === 0,
                    summaryText: `Toplam ${totalLinesRead} satır okundu, ${results.length} geçerli akış işlendi${skippedRows > 0 ? ` (${skippedRows} geçersiz/boş satır atlandı)` : ' (atlanan satır yok)'}.`
                },
                schemaMapping,
                driftAnalysis: {
                    ...driftAnalysis,
                    summaryText: driftSummaryText
                },
                classDistribution,
                repeatedIps,
                evaluation,
                results
            });
        })
        .on('error', err => res.status(500).json({ error: 'CSV hatası: ' + err.message }));
});

// Karantina Yönetimi Uç Noktaları
app.get('/api/quarantine', (req, res) => res.json(readJsonSafe(quarantineFilePath)));

app.post('/api/quarantine', (req, res) => {
    const { ip, reason } = req.body || {};
    if (!ip || !String(ip).trim()) return res.status(400).json({ error: 'IP adresi gerekli.' });
    const cleanIp = String(ip).trim();
    const list = readJsonSafe(quarantineFilePath);
    const existingIndex = list.findIndex(i => i.ip === cleanIp);

    const isPrivate = isPrivateIp(cleanIp);
    const ipScope = isPrivate ? 'Yerel Ağ (Özel IP - RFC 1918)' : 'Dış Ağ (Genel IP)';

    if (existingIndex >= 0) {
        list[existingIndex].triggerCount = (list[existingIndex].triggerCount || 1) + 1;
        list[existingIndex].reason = reason || list[existingIndex].reason;
        list[existingIndex].lastSeen = new Date().toISOString();
        list[existingIndex].isPrivate = isPrivate;
        list[existingIndex].ipScope = ipScope;
    } else {
        list.unshift({
            ip: cleanIp,
            reason: reason || 'Yüksek riskli ağ trafiği',
            triggerCount: 1,
            isPrivate,
            ipScope,
            addedAt: new Date().toISOString(),
            lastSeen: new Date().toISOString()
        });
    }

    writeJsonSafe(quarantineFilePath, list, 200);
    res.json(list);
});

app.delete('/api/quarantine/:ip', (req, res) => {
    const target = decodeURIComponent(req.params.ip);
    const updated = readJsonSafe(quarantineFilePath).filter(i => i.ip !== target);
    writeJsonSafe(quarantineFilePath, updated, 200);
    res.json(updated);
});

/**
 * Denetlenebilir, Tekrarlanabilir UTF-8 BOM CSV Rapor Üreteci
 */
function generateCsvReport(logs = [], quarantineList = []) {
    const BOM = '\uFEFF';
    const lines = [];

    const escapeCsv = (val) => {
        if (val === null || val === undefined) return '""';
        return `"${String(val).replace(/"/g, '""')}"`;
    };

    // Metadata ve Sistem Başlığı (Tekrarlanabilirlik ve Veri Kalitesi)
    lines.push('=== AĞ GÜVENLİK VE OLAY DENETİM RAPORU (XAI KARAR AĞACI) ===');
    lines.push(`Kural Seti Sürümü,${escapeCsv('cyber_xai_tree v2.4 (Karar Ağaçları & Açıklanabilir Yapay Zeka)')}`);
    lines.push(`Rapor Analiz Zamanı,${escapeCsv(new Date().toLocaleString('tr-TR'))}`);
    lines.push(`Toplam Kayıtlı Olay Sayısı,${escapeCsv(logs.length)}`);
    lines.push(`Aktif Karantinadaki IP Sayısı,${escapeCsv(quarantineList.length)}`);

    // Tekrarlanabilirlik ve Veri Kalitesi Bilgileri
    const batchMeta = lastBatchQualityInfo;
    if (batchMeta && batchMeta.totalLinesRead !== null && batchMeta.totalLinesRead !== undefined) {
        lines.push(`Eşlenen Veri Seti / Kaynak,${escapeCsv(batchMeta.datasetName || 'Standart Veri Seti')}`);
        lines.push(`Şema Eşleme Özeti,${escapeCsv(batchMeta.schemaMappingSummary || 'Standart Sütun Eşlemesi')}`);
        lines.push(`Toplam Okunan Satır Sayısı,${escapeCsv(batchMeta.totalLinesRead)}`);
        lines.push(`Geçerli İşlenen Satır Sayısı,${escapeCsv(batchMeta.validRowsProcessed)}`);
        lines.push(`Atlanan (Geçersiz/Boş) Satır Sayısı,${escapeCsv(batchMeta.skippedRowsCount)}`);
        lines.push(`Veri Kalite Durumu,${escapeCsv(batchMeta.skippedRowsCount === 0 ? 'Tam Bütünlük (0 Atlanan Satır)' : `${batchMeta.skippedRowsCount} Satır Atlandı (Veri Temizliği Yapıldı)`)}`);
    } else {
        const manualCount = logs.filter(l => l.source === 'Manuel Analiz').length;
        const batchCount = logs.filter(l => l.source === 'CSV Toplu Analiz').length;
        lines.push(`Eşlenen Veri Seti / Kaynak,${escapeCsv(`Sistem Olay Günlükleri (Toplu: ${batchCount}, Tekil: ${manualCount})`)}`);
        lines.push(`Toplam Okunan Satır Sayısı,${escapeCsv(logs.length)}`);
        lines.push(`Geçerli İşlenen Satır Sayısı,${escapeCsv(logs.length)}`);
        lines.push(`Atlanan (Geçersiz/Boş) Satır Sayısı,${escapeCsv(0)}`);
        lines.push(`Veri Kalite Durumu,${escapeCsv('Tam Bütünlük (0 Atlanan Satır)')}`);
    }
    lines.push('');

    // BÖLÜM 1: GÜVENLİK KARANTİNA LİSTESİ
    lines.push('=== 1. GÜVENLİK KARANTİNA LİSTESİ ===');
    lines.push('Hedef IP Adresi,Ağ Kapsamı,Karantina Gerekçesi,Tetiklenme Sayısı,Eklenme Tarihi');
    if (!quarantineList || quarantineList.length === 0) {
        lines.push('Karantinaya alınmış IP adresi bulunmuyor,,,,');
    } else {
        quarantineList.forEach(item => {
            const dateStr = item.addedAt ? new Date(item.addedAt).toLocaleString('tr-TR') : '-';
            lines.push([
                escapeCsv(item.ip || '-'),
                escapeCsv(item.ipScope || (isPrivateIp(item.ip) ? 'Yerel Ağ (Özel IP)' : 'Dış Ağ (Genel IP)')),
                escapeCsv(item.reason || '-'),
                escapeCsv(item.triggerCount || 1),
                escapeCsv(dateStr)
            ].join(','));
        });
    }
    lines.push('');

    // BÖLÜM 2: AĞ TRAFİĞİ ANALİZ GEÇMİŞİ VE OLAY GÜNLÜKLERİ
    lines.push('=== 2. AĞ TRAFİĞİ ANALİZ VE OLAY GÜNLÜKLERİ ===');
    lines.push('Tarih / Saat,Kaynak IP,Ağ Kapsamı,Analiz Kaynağı,Tespit Edilen Sınıf,Risk Seviyesi,Risk Skoru,Karar Güven Oranı,Paket Boyutu (B),Süre (sn),Port Türü,Hatalı Giriş,İstek Hızı (req/s),İzlenen Karar Yolu Adımları,Önerilen Güvenlik Müdahalesi');
    if (!logs || logs.length === 0) {
        lines.push('Kayıtlı analiz günlüğü bulunmuyor,,,,,,,,,,,,,,');
    } else {
        logs.forEach(log => {
            const out = log.output || {};
            const inp = log.input || {};
            const dateStr = log.timestamp ? new Date(log.timestamp).toLocaleString('tr-TR') : '-';
            const portStr = inp.isKnownPort ? 'Standart Port' : 'Bilinmeyen Port';
            const pathSteps = Array.isArray(out.decisionPath)
                ? out.decisionPath.map(p => `${p.node}: ${p.rule || p.condition} -> ${p.branch}`).join(' | ')
                : '-';

            lines.push([
                escapeCsv(dateStr),
                escapeCsv(inp.sourceIp || '-'),
                escapeCsv(inp.ipScope || (isPrivateIp(inp.sourceIp) ? 'Yerel Ağ' : 'Dış Ağ')),
                escapeCsv(log.source || '-'),
                escapeCsv(out.attackType || '-'),
                escapeCsv(out.riskLevel || '-'),
                escapeCsv(out.riskScore !== undefined ? out.riskScore : '-'),
                escapeCsv(out.confidence !== undefined ? `%${out.confidence}` : '-'),
                escapeCsv(inp.packetSize !== undefined ? inp.packetSize : '-'),
                escapeCsv(inp.duration !== undefined ? inp.duration : '-'),
                escapeCsv(portStr),
                escapeCsv(inp.failedLogins !== undefined ? inp.failedLogins : '-'),
                escapeCsv(inp.requestRate !== undefined ? inp.requestRate : '-'),
                escapeCsv(pathSteps),
                escapeCsv(out.recommendation || '-')
            ].join(','));
        });
    }

    return BOM + lines.join('\r\n');
}

app.get('/api/logs', (req, res) => res.json(readJsonSafe(logFilePath)));
app.delete('/api/logs', (req, res) => {
    writeJsonSafe(logFilePath, [], 1000);
    res.json({ ok: true });
});

// CSV Rapor İndirme Uç Noktası (UTF-8 BOM ile Excel uyumlu)
app.get('/api/logs/download-csv', (req, res) => {
    const logs = readJsonSafe(logFilePath);
    const quarantineList = readJsonSafe(quarantineFilePath);
    const csvContent = generateCsvReport(logs, quarantineList);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="ag_guvenlik_olay_raporu.csv"');
    res.send(csvContent);
});

// Geriye dönük uyumluluk: /api/logs/download varsayılan olarak UTF-8 CSV sunar, ?format=json ile JSON verir
app.get('/api/logs/download', (req, res) => {
    if (req.query.format === 'json') {
        return res.download(logFilePath, 'ag_guvenlik_olay_raporu.json');
    }
    const logs = readJsonSafe(logFilePath);
    const quarantineList = readJsonSafe(quarantineFilePath);
    const csvContent = generateCsvReport(logs, quarantineList);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="ag_guvenlik_olay_raporu.csv"');
    res.send(csvContent);
});

app.listen(PORT, () => console.log(`cyber_xai_tree aktif: http://localhost:${PORT}`));
