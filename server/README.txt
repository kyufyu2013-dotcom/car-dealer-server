Car Dealer Central Server v7.1 / API 2.2.1

重點修正：
1. 同一台車不可同時存在兩筆「待確認」成交申請。
2. 已售車輛不可再次確認成交。
3. 業務成交申請、後台直接成交、確認、駁回全部改為伺服器端交易鎖定。
4. 確認成交 API 使用 PostgreSQL FOR UPDATE，避免兩個裝置同時確認造成重複成交。
5. 管理員整份 snapshot 上傳也會檢查重複成交完整性。
6. 保留 v7 業務手機版與 Super Admin API。

部署：
將 server.js、package.json、public/ 全部覆蓋 GitHub repo 的 server/ 內容，Render 自動部署。
完成後 /api/health 應顯示 version: 2.2.1。

注意：已經存在於測試資料中的舊重複成交紀錄不會自動刪除，避免誤刪真實歷史。


v7.2 新增：車行後台可取消誤按的已確認成交並恢復在庫。取消必填原因，成交申請保留為『成交已取消』歷史紀錄，不刪除稽核軌跡。
