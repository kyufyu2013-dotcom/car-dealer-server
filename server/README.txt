中古車中央伺服器 v7｜業務手機/電腦跨裝置版

版本：Server 2.2.0

這版是在 v6 Super Admin 雲端版上增加：
1. /sales/ 業務手機 Web App，直接由同一個 Render Web Service 提供。
2. 業務登入、Session Restore、3 秒同步。
3. 業務可看：在庫車基本資料、公司底價、檢驗證照片、入庫照片。
4. 業務可提交成交申請並查看自己的申請/駁回原因/預估獎金。
5. 伺服器端真正過濾敏感資料：業務 API 不再收到購入價、整備成本、總成本、來源、來源備註、公司利潤、其他業務資料。
6. 原 v4.4 車行 Windows 客戶端與 v6 Super Admin API 保留。

部署：
- 把 server.js、package.json、public/ 整個放到 GitHub repo 的 server/ 目錄。
- Render 自動部署後，先測 /api/health，應看到 version 2.2.0。
- 手機直接開：https://car-dealer-server-g3c9.onrender.com/sales/
- 用「車行代碼 + 業務帳號 + 密碼」登入。

重要：
- 業務帳號必須先由該車行 Admin 在 Windows 客戶端建立並成功同步到中央伺服器。
- 這版把業務敏感資料防護移到伺服器端，不只是前端隱藏。
- Render 免費方案休眠後第一次開啟可能要等數十秒。
