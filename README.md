# SSH Log Analyzer

Linux auth.log dosyalarındaki başarısız SSH giriş denemelerini analiz eden Python aracı.

## Özellikler
- En çok deneme yapan IP'leri listeler
- En çok denenen kullanıcı adlarını gösterir
- Saate göre deneme dağılımını çıkarır
- Sonuçları CSV olarak kaydeder

## Kullanım
```
python log_analyzer.py auth.log --top 5 --csv rapor.csv
```

## Örnek çıktı
```
Toplam başarısız giriş denemesi: 5

En çok deneme yapan 5 IP:
 203.0.113.5        3
 198.51.100.7       2
```