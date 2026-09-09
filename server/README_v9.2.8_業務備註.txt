Server v9.2.8 / API 2.4.10
- 新增 Sales-safe 欄位 salesNote（業務備註）
- 業務庫存可顯示並搜尋車輛備註
- salesNote 不含成本/來源/利潤資料，且完整內容仍由 Dealer Node salesInventory relay 提供
- 中央 operational shadow 不永久保存 salesNote
- 保留 v9.2.7 注音/英文連續搜尋修正與既有安全過濾
