Server v9.2.3 / API 2.4.5
- 修正業務照片 API 讀 snapshots 不存在的 data 欄位造成 HTTP 500；改讀正確 json 欄位。
- 移除業務照片視窗的 Dealer Node/中央資料庫說明文字。
- 照片仍維持按需由 Dealer Node 回傳，中央不永久保存照片內容。
