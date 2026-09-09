Server v9.2.5 / API 2.4.7
- 登入不再查 Node 狀態，避免 Node 狀態異常連帶造成登入 500。
- 車行主機狀態改成登入後用 authenticated /api/node/status 查詢。
- 新增 Sales 專用 Dealer Node 庫存按需讀取。
- 業務庫存改從車行 Node 取安全欄位，不含成本、來源、公司利潤。
