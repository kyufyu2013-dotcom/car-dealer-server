庫車掌盤 Server v8.0
API version: 2.3.0

新增：
- Super Admin 雲端資料中心直接掛載在 /admin/
- 業務行動版仍在 /sales/
- /admin/ 與 /sales/ 都使用 no-store，避免舊版快取
- Super Admin 同源使用 /api，不再綁死特定網域
- Super Admin 帳號頁補上業務底薪欄位

網址：
- Super Admin: /admin/
- 業務端: /sales/
- 健康檢查: /api/health

Render 部署完成後 /api/health 應顯示 version 2.3.0。
