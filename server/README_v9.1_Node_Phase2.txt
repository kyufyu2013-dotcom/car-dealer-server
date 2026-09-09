庫車掌盤 Server v9.1 / API 2.4.1
Dealer Node 第二階段：Super Admin 按需即時讀取

新增：
- dealer_node_requests 暫時 Relay 佇列表
- Super Admin 可向在線 Dealer Node 發出 companyData / vehicleDetail / vehiclePhoto 請求
- Dealer Node 只需主動對中央 Server 輪詢，不需要開放車行路由器 Port
- Super Admin 不需要車行端逐次按同意；權限由平台端既有 platformAdmin 驗證
- 車行資料來源為 Desktop 本機 SQLite dealer-node.sqlite3
- 車輛列表不傳照片內容，只回傳照片數量
- 點車輛才讀取該車詳細資料
- 點某一張照片才傳該張照片，不一次上傳整車照片
- Relay 結果被 Super Admin 讀取後立即從 dealer_node_requests 刪除
- Node 離線時 Super Admin 目前仍可顯示 PostgreSQL 舊架構相容副本，避免遷移期功能中斷

注意：
- PostgreSQL snapshots 目前仍保留，尚未正式切成 Local-only。
- 下一階段才會將完整車行業務資料逐類移出中央 snapshot，並設計手機業務端的輕量雲端資料層。
