庫車掌盤 Server v9.2 / API 2.4.2 — Dealer Node Phase 3 Local-first

核心變更
- Desktop v5.3 Dealer Node 本機 SQLite 成為完整車行資料主體。
- v5.3 Node heartbeat 確認本機 DB 存在後，中央 PostgreSQL snapshot 自動降級為 operational shadow。
- PostgreSQL 不再永久保存：購入價、整備成本、總成本、來源/備註、照片、公司利潤、成交費用、詳細 operationLogs、salaryHistory。
- 中央保留帳號/密碼 hash/授權/Node 身分，以及手機業務端所需的基本庫存、底價、成交申請與狀態。
- Super Admin 完整資料維持按需 Dealer Node 即時讀取；Node 離線時無法讀取本機私有欄位。
- 成交確認只短暫提交 localTotalCost 用於伺服器交易鎖驗證/計算，私有成本不寫入 PostgreSQL snapshot。
- SalesSafeSnapshot 仍保留。

安全遷移
只有 v5.3 heartbeat 且 localDataBytes > 0 才會把該車行舊 cloud snapshot 降級，避免 Server 先部署時就刪掉尚未建立本機資料的車行。
