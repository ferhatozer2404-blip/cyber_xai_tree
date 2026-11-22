const http = require('http');

const TEST_PORT = 3037;
process.env.PORT = String(TEST_PORT);

// Requiring server.js starts the app on TEST_PORT
require('../server.js');

setTimeout(async () => {
    try {
        await runAllTests();
        console.log('\n======================================================');
        console.log('TÜM AKADEMİK VE SOC DOĞRULAMA TESTLERİ BAŞARIYLA GEÇTİ!');
        console.log('======================================================\n');
        process.exit(0);
    } catch (err) {
        console.error('\n[HATA] Doğrulama testi başarısız:', err);
        process.exit(1);
    }
}, 800);

function request(path, options = {}) {
    return new Promise((resolve, reject) => {
        const reqOptions = {
            hostname: '127.0.0.1',
            port: TEST_PORT,
            path,
            method: options.method || 'GET',
            headers: options.headers || {}
        };

        const req = http.request(reqOptions, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                resolve({
                    status: res.statusCode,
                    headers: res.headers,
                    body: data
                });
            });
        });

        req.on('error', reject);

        if (options.body) {
            req.write(typeof options.body === 'string' ? options.body : JSON.stringify(options.body));
        }
        req.end();
    });
}

async function runAllTests() {
    console.log('[TEST 1] Statik Sayfalar ve Varlıklar Kontrolü');
    const pages = ['/index.html', '/batch.html', '/logs.html', '/style.css', '/app.js'];
    for (const p of pages) {
        const res = await request(p);
        if (res.status !== 200) throw new Error(`Statik dosya ${p} durum kodu: ${res.status}`);
        console.log(`  - ${p}: 200 OK (${res.body.length} bayt)`);
    }

    console.log('\n[TEST 2] Marka, Başlık ve Sade Tasarım Kontrolü');
    const indexHtml = (await request('/index.html')).body;
    const batchHtml = (await request('/batch.html')).body;
    const logsHtml = (await request('/logs.html')).body;
    const styleCss = (await request('/style.css')).body;
    const appJs = (await request('/app.js')).body;

    const allPages = [
        { name: 'index.html', content: indexHtml },
        { name: 'batch.html', content: batchHtml },
        { name: 'logs.html', content: logsHtml }
    ];

    for (const page of allPages) {
        if (!page.content.includes('Ağ Trafiği Sınıflandırma Sistemi')) {
            throw new Error(`${page.name} içinde 'Ağ Trafiği Sınıflandırma Sistemi' başlığı bulunamadı`);
        }
        if (page.content.includes('SOC MONİTÖR: AKTİF') || page.content.includes('XAI Tree v2.4')) {
            throw new Error(`${page.name} içinde kaldırılması gereken yapay rozetler mevcut`);
        }
        if (page.content.includes('cyberShieldGrad') || page.content.includes('cyber_xai_tree_rapor')) {
            throw new Error(`${page.name} içinde eski kalkan logosu veya eski dosya adı bulundu`);
        }
    }
    console.log('  - Tüm sayfalarda temiz tipografik başlık ve sade kurumsal tema mevcut.');

    console.log('\n[TEST 3] Arayüzdeki Tüm Emojilerin Temizlendiğinin Doğrulanması');
    const emojiRegex = /[\u{1F300}-\u{1F9FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}\u{1F1E6}-\u{1F1FF}\u{1F600}-\u{1F64F}\u{1F680}-\u{1F6FF}]/u;
    const filesToCheck = [
        { name: 'index.html', text: indexHtml },
        { name: 'batch.html', text: batchHtml },
        { name: 'logs.html', text: logsHtml },
        { name: 'app.js', text: appJs },
        { name: 'style.css', text: styleCss }
    ];
    for (const f of filesToCheck) {
        const lines = f.text.split('\n');
        lines.forEach((l, i) => {
            if (emojiRegex.test(l)) {
                throw new Error(`${f.name} Satır ${i + 1} içinde emoji tespit edildi: "${l.trim()}"`);
            }
        });
    }
    console.log('  - 5 ana arayüz dosyasında 0 emoji tespit edildi (Tamamen temiz).');

    console.log('\n[TEST 4] Tekil Analiz: Karar Yolu, Katkı Analizi, Karşı-Olgusal, Sınır Duyarlılığı, SOC Playbook');
    const ddosRes = await request('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: {
            sourceIp: '185.220.101.42',
            packetSize: 2450,
            duration: 0.1,
            isKnownPort: true,
            failedLogins: 0,
            requestRate: 140
        }
    });

    if (ddosRes.status !== 200) throw new Error(`/api/analyze hata: ${ddosRes.status}`);
    const ddosData = JSON.parse(ddosRes.body);

    if (ddosData.attackType !== 'DDoS / Flood Saldırısı') {
        throw new Error(`Beklenen saldırı türü 'DDoS / Flood Saldırısı', gelen: ${ddosData.attackType}`);
    }

    // Karar Yolu Kontrolü
    if (!Array.isArray(ddosData.decisionPath) || ddosData.decisionPath.length < 3) {
        throw new Error('Karar yolu adımları eksik veya geçersiz');
    }
    const rootStep = ddosData.decisionPath[0];
    if (!rootStep.node || !rootStep.condition || !rootStep.actualValue || !rootStep.threshold || !rootStep.branch) {
        throw new Error('Karar yolu adımı gerekli XAI alanlarını içermiyor');
    }
    console.log(`  - Karar Yolu: ${ddosData.decisionPath.length} adım (Kök: ${rootStep.condition} -> ${rootStep.branch})`);

    // Dinamik Özellik Katkı Analizi Kontrolü
    if (!Array.isArray(ddosData.featureAttribution) || ddosData.featureAttribution.length !== 5) {
        throw new Error('Özellik etki dağılımı 5 parametreyi eksiksiz içermelidir');
    }
    console.log(`  - Özellik Katkı Analizi: En yüksek ağırlık: ${ddosData.featureAttribution[0].label} (%${ddosData.featureAttribution[0].weight})`);

    // Karşı-Olgusal Analiz (Sparsity & Cost)
    const cf = ddosData.counterfactuals;
    if (!cf || cf.targetClass !== 'Normal Trafik' || typeof cf.sparsity !== 'number' || typeof cf.cost !== 'number') {
        throw new Error('Karşı-Olgusal analiz sparsity veya cost değerlerini içermiyor');
    }
    if (!Array.isArray(cf.changes) || cf.changes.length === 0) {
        throw new Error('Karşı-Olgusal değişim parametreleri listesi boş');
    }
    console.log(`  - Karşı-Olgusal Analiz: Hedef: ${cf.targetClass}, Sparsity: ${cf.sparsity}, Cost: ${cf.cost}`);

    // Sınır Duyarlılığı ve Güven
    const sens = ddosData.boundarySensitivity;
    if (!sens || !sens.sensitivityLevel || typeof sens.marginPercentage !== 'number' || typeof ddosData.confidence !== 'number') {
        throw new Error('Sınır duyarlılığı veya güven skoru eksik');
    }
    console.log(`  - Sınır Duyarlılığı: ${sens.sensitivityLevel} (Eşik Mesafesi: %${sens.marginPercentage}, Model Güveni: %${ddosData.confidence})`);

    // SOC Playbook & İç Ağ Kontrolü
    const pb = ddosData.socPlaybook;
    if (!pb || !Array.isArray(pb.steps) || pb.steps.length === 0) {
        throw new Error('SOC Playbook müdahale adımları bulunamadı');
    }
    console.log(`  - SOC Playbook: ${pb.title} (${pb.steps.length} adım)`);

    // İç Ağ Testi (RFC 1918)
    const privateRes = await request('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: {
            sourceIp: '192.168.1.55',
            packetSize: 3200,
            duration: 15,
            isKnownPort: false,
            failedLogins: 0,
            requestRate: 20
        }
    });
    const privData = JSON.parse(privateRes.body);
    if (!privData.input.isPrivate || !privData.socPlaybook.privateWarning) {
        throw new Error('192.168.1.55 için iç ağ tespiti veya iç ağ uyarısı üretilmedi');
    }
    console.log(`  - İç Ağ (RFC 1918) Tespiti ve Uyarısı: ${privData.input.sourceIp} -> ${privData.socPlaybook.privateWarning}`);

    console.log('\n[TEST 5] CSV Toplu Analiz: Veri Kalitesi, Karışıklık Matrisi, Makro-F1, FN/FP ve Drift');
    const sampleBatchCSV = [
        'Kaynak IP, Paket Boyutu, Süre, Bilinen Port, Hatalı Giriş, İstek Hızı, Gerçek Etiket',
        '185.220.101.42, 2450, 0.1, true, 0, 140, DDoS / Flood Saldırısı',
        '91.132.44.19, 420, 6.5, false, 8, 25, Kaba Kuvvet (Brute-Force) Saldırısı',
        '45.83.64.11, 110, 0.05, false, 0, 65, Port Taraması ve Keşif Aktivitesi',
        '172.16.40.88, 3800, 12.4, false, 0, 15, Veri Sızdırma / Şüpheli Transfer',
        '192.168.1.24, 540, 1.6, true, 0, 12, Normal Trafik',
        '185.220.101.42, 2500, 0.12, true, 0, 145, DDoS / Flood Saldırısı',
        ',,,,,', // Boş satır 1 (tolerans testi)
        ',,,,,'  // Boş satır 2 (tolerans testi)
    ].join('\n');

    const batchRes = await request('/api/analyze-csv', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: { csvContent: sampleBatchCSV }
    });

    if (batchRes.status !== 200) throw new Error(`/api/analyze-csv hata: ${batchRes.status}`);
    const batchData = JSON.parse(batchRes.body);

    // Veri Kalitesi Özeti Kontrolü
    if (!batchData.dataQuality || batchData.dataQuality.skippedRowsCount !== 2 || batchData.dataQuality.validRowsProcessed !== 6) {
        throw new Error(`Veri kalitesi atlanan satır hesabı hatalı: ${JSON.stringify(batchData.dataQuality)}`);
    }
    console.log(`  - Veri Kalitesi Özeti: Okunan: ${batchData.dataQuality.totalLinesRead}, İşlenen: ${batchData.dataQuality.validRowsProcessed}, Atlanan Hatalı/Boş: ${batchData.dataQuality.skippedRowsCount}`);

    // Akademik Değerlendirme & Karışıklık Matrisi
    const ev = batchData.evaluation;
    if (!ev || ev.accuracy !== 100 || ev.macroF1 !== 100 || ev.weightedF1 !== 100) {
        throw new Error(`Akademik değerlendirme metrikleri hatalı: ${JSON.stringify(ev)}`);
    }
    console.log(`  - Akademik Metrikler: Accuracy: %${ev.accuracy}, Macro-F1: %${ev.macroF1}, Weighted-F1: %${ev.weightedF1}`);

    if (!ev.confusionMatrix || !ev.confusionMatrix.matrix) {
        throw new Error('Confusion Matrix tablosu üretilmedi');
    }
    console.log(`  - Karışıklık Matrisi (Confusion Matrix): ${ev.confusionMatrix.classes.length} sınıf haritalandı`);

    if (!ev.securitySummary || ev.securitySummary.falseNegatives !== 0) {
        throw new Error('Güvenlik Yanlış Negatif özeti hatalı');
    }
    console.log(`  - Güvenlik Özeti (FN/FP): Kaçırılan Saldırı (FN): ${ev.securitySummary.falseNegatives}, Yanlış Alarm (FP): ${ev.securitySummary.falsePositives}`);

    // Tekrarlı IP Özeti
    if (!Array.isArray(batchData.repeatedIps) || batchData.repeatedIps.length === 0) {
        throw new Error('Tekrarlı IP özeti üretilmedi (185.220.101.42 2 kez mevcuttu)');
    }
    const repIp = batchData.repeatedIps.find(r => r.ip === '185.220.101.42');
    if (!repIp || repIp.flowCount !== 2) {
        throw new Error('185.220.101.42 için 2 akış sayısı tespit edilemedi');
    }
    console.log(`  - Tekrarlı Şüpheli IP: ${repIp.ip} (${repIp.flowCount} akış, Risk: ${repIp.highestRisk})`);

    // Dağılım Kayması (Drift) Kontrolü (İkinci batch göndererek drift hesaplama)
    const secondBatchCSV = [
        'Kaynak IP, Paket Boyutu, Süre, Bilinen Port, Hatalı Giriş, İstek Hızı, Gerçek Etiket',
        '185.220.101.42, 2450, 0.1, true, 0, 140, DDoS / Flood Saldırısı',
        '185.220.101.42, 2600, 0.1, true, 0, 160, DDoS / Flood Saldırısı',
        '185.220.101.42, 2700, 0.1, true, 0, 180, DDoS / Flood Saldırısı',
        '192.168.1.24, 540, 1.6, true, 0, 12, Normal Trafik'
    ].join('\n');

    const driftRes = await request('/api/analyze-csv', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: { csvContent: secondBatchCSV }
    });
    const driftData = JSON.parse(driftRes.body);
    if (!driftData.driftAnalysis || !driftData.driftAnalysis.hasPreviousBatch) {
        throw new Error('İkinci toplu analizde drift hesabı devreye girmedi');
    }
    console.log(`  - Dağılım Kayması (Drift): Önceki analize göre hesaplandı (Belirgin kayma: ${driftData.driftAnalysis.significantDriftDetected})`);

    console.log('\n[TEST 6] Karantina Yönetimi & Tekrarlanabilir UTF-8 CSV Raporu');
    // Karantinaya ekle
    const qAddRes = await request('/api/quarantine', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: { ip: '198.51.100.99', reason: 'Otomatik Test Karantinası' }
    });
    const qList1 = JSON.parse(qAddRes.body);
    const item1 = qList1.find(i => i.ip === '198.51.100.99');
    if (!item1 || item1.triggerCount !== 1 || !item1.ipScope) {
        throw new Error('Karantina öğesi triggerCount veya ipScope içermiyor');
    }

    // Aynı IP'yi tekrar ekle (triggerCount artmalı)
    const qAddRes2 = await request('/api/quarantine', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: { ip: '198.51.100.99', reason: 'Tekrarlayan Test Saldırısı' }
    });
    const qList2 = JSON.parse(qAddRes2.body);
    const item2 = qList2.find(i => i.ip === '198.51.100.99');
    if (!item2 || item2.triggerCount !== 2) {
        throw new Error(`Tekrarlanan karantina için triggerCount 2 olmalı, gelen: ${item2 ? item2.triggerCount : 'yok'}`);
    }
    console.log(`  - Karantina Tetiklenme Sayacı (Trigger Count): ${item2.ip} -> ${item2.triggerCount} kez tetiklendi (${item2.ipScope})`);

    // Karantinadan kaldır
    const qDelRes = await request('/api/quarantine/198.51.100.99', { method: 'DELETE' });
    const qList3 = JSON.parse(qDelRes.body);
    if (qList3.some(i => i.ip === '198.51.100.99')) {
        throw new Error('Karantinadan kaldırma işlemi başarısız');
    }
    console.log('  - Karantinadan Çıkar işlevi başarıyla doğrulandı.');

    // UTF-8 BOM CSV Rapor İndirme Uç Noktası
    const csvReportRes = await request('/api/logs/download-csv');
    if (csvReportRes.status !== 200) throw new Error(`/api/logs/download-csv durum: ${csvReportRes.status}`);
    if (!csvReportRes.body.startsWith('\uFEFF')) {
        throw new Error('CSV raporu başında UTF-8 BOM (\uFEFF) bulunamadı');
    }
    if (!csvReportRes.body.includes('cyber_xai_tree v2.4') || !csvReportRes.body.includes('GÜVENLİK KARANTİNA LİSTESİ')) {
        throw new Error('CSV raporunda sürüm veya karantina bölümü eksik');
    }
    if (!csvReportRes.body.includes('Toplam Okunan Satır Sayısı') ||
        !csvReportRes.body.includes('Geçerli İşlenen Satır Sayısı') ||
        !csvReportRes.body.includes('Atlanan (Geçersiz/Boş) Satır Sayısı') ||
        !csvReportRes.body.includes('Eşlenen Veri Seti / Kaynak')) {
        throw new Error('CSV raporunda tekrarlanabilirlik ve veri kalitesi meta satırları eksik');
    }
    console.log(`  - Denetlenebilir UTF-8 BOM CSV Raporu: ${csvReportRes.body.length} bayt (Sürüm v2.4, meta satırları ve Excel uyumluluğu tam)`);

    console.log('\n[TEST 7] Karar Ağacı ve Büyüteç Vektörel İkon ve Favicon Doğrulaması');
    const favSvgRes = await request('/favicon.svg');
    if (favSvgRes.status !== 200) throw new Error('/favicon.svg bulunamadı');
    if (!favSvgRes.body.includes('stroke="#38BDF8"') || !favSvgRes.body.includes('r="6.5"')) {
        throw new Error('/favicon.svg içinde turkuaz karar ağacı ve büyüteç tasarımı bulunamadı');
    }

    const htmlPages = [
        { name: 'index.html', text: (await request('/index.html')).body },
        { name: 'batch.html', text: (await request('/batch.html')).body },
        { name: 'logs.html', text: (await request('/logs.html')).body }
    ];

    for (const hp of htmlPages) {
        if (!hp.text.includes('data:image/svg+xml')) {
            throw new Error(`${hp.name} içinde data:image/svg+xml favicon linki bulunamadı`);
        }
        if (!hp.text.includes('brand-branch-icon') || !hp.text.includes('14.6 14.6L20.5 20.5')) {
            throw new Error(`${hp.name} üst başlığında karar ağacı ve büyüteç ikonu bulunamadı`);
        }
        console.log(`  - ${hp.name}: data:image/svg+xml favicon ve üst başlık ikonu başarıyla doğrulandı`);
    }

    console.log('\n[TEST 8] Standart Veri Seti Şema Eşleme (CIC-IDS2017 & UNSW-NB15)');
    const cicCsv = [
        'Source IP,Total Length of Fwd Packets,Flow Duration,Destination Port,Flow Packets/s,Label',
        '192.168.10.5,2450,150000,80,140,DDoS',
        '10.0.0.15,110,50000,5353,65,PortScan'
    ].join('\n');

    const cicRes = await request('/api/analyze-csv', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: { csvContent: cicCsv }
    });
    const cicData = JSON.parse(cicRes.body);
    if (!cicData.schemaMapping || !cicData.schemaMapping.datasetName.includes('CIC-IDS2017')) {
        throw new Error(`CIC-IDS2017 şeması tespit edilemedi: ${JSON.stringify(cicData.schemaMapping)}`);
    }
    if (!cicData.schemaMapping.summaryText || !cicData.schemaMapping.summaryText.includes('CIC-IDS2017')) {
        throw new Error('CIC-IDS2017 özet metni oluşturulamadı');
    }
    if (cicData.results.length !== 2) {
        throw new Error(`CIC-IDS2017 satırları işlenemedi: ${cicData.results.length}`);
    }
    console.log(`  - CIC-IDS2017 Eşleme: ${cicData.schemaMapping.summaryText}`);

    const unswCsv = [
        'srcip,sbytes,dur,sport,rate,attack_cat',
        '175.45.176.0,420,6.5,443,25,Reconnaissance'
    ].join('\n');

    const unswRes = await request('/api/analyze-csv', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: { csvContent: unswCsv }
    });
    const unswData = JSON.parse(unswRes.body);
    if (!unswData.schemaMapping || unswData.schemaMapping.datasetName !== 'UNSW-NB15') {
        throw new Error(`UNSW-NB15 şeması tespit edilemedi: ${JSON.stringify(unswData.schemaMapping)}`);
    }
    if (!unswData.driftAnalysis || !unswData.driftAnalysis.summaryText) {
        throw new Error('Toplu analiz drift summaryText içermiyor');
    }
    console.log(`  - UNSW-NB15 Eşleme: ${unswData.schemaMapping.summaryText}`);
    console.log(`  - Dağılım Farkı Özeti: ${unswData.driftAnalysis.summaryText}`);

    console.log('\n[TEST 9] Mobil & Tablet Responsive Kontrolü (360px, 480px, 768px, 1024px)');
    const allHtmls = [
        { name: 'index.html', html: (await request('/index.html')).body },
        { name: 'batch.html', html: (await request('/batch.html')).body },
        { name: 'logs.html', html: (await request('/logs.html')).body }
    ];

    for (const h of allHtmls) {
        if (!h.html.includes('<meta name="viewport" content="width=device-width, initial-scale=1.0">')) {
            throw new Error(`${h.name} içinde eksiksiz viewport meta etiketi bulunamadı`);
        }
        console.log(`  - ${h.name}: Viewport meta etiketi eksiksiz`);
    }

    const cssContent = (await request('/style.css')).body;
    if (!cssContent.includes('overflow-x: hidden') || !cssContent.includes('overflow-wrap: anywhere')) {
        throw new Error('style.css içinde taşma koruması (overflow-x: hidden / overflow-wrap: anywhere) eksik');
    }
    if (!cssContent.includes('@media (max-width: 1024px)') ||
        !cssContent.includes('@media (max-width: 768px)') ||
        !cssContent.includes('@media (max-width: 480px)') ||
        !cssContent.includes('@media (max-width: 360px)')) {
        throw new Error('style.css içinde 1024px, 768px, 480px ve 360px responsive kuralları eksik');
    }
    if (!cssContent.includes('.table-wrap') || !cssContent.includes('white-space: nowrap !important')) {
        throw new Error('style.css içinde table-wrap veya rozet white-space kuralları eksik');
    }
    console.log('  - style.css: 360px, 480px, 768px ve 1024px responsive kuralları ve taşma koruması doğrulandı.');
}
