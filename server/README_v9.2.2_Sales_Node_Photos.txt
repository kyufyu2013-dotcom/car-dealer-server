Server v9.2.2 / API 2.4.4
- 修正 Local-first 後業務行動端看不到照片。
- 中央 PostgreSQL 只保留照片張數，不永久保存照片內容。
- Sales 只能讀自己車行、在庫車輛的照片。
- 點某一張照片時才由 Dealer Node 回傳該張，讀完即刪除中央 relay 暫存。
- SalesSafeSnapshot 的成本/來源/利潤保護維持不變。
