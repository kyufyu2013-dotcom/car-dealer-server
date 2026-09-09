庫車掌盤 Server v9.2.1 / API 2.4.3 — Dealer Node 離線狀態修正版
- 新增 POST /api/node/offline。
- Desktop 登出/關閉時立即標記 Node 離線。
- 未完成的 Node 讀取立即失敗，不再卡住。
- heartbeat 重新到達即恢復在線。
