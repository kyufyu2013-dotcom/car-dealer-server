庫車掌盤 Server v8.4 / API 2.3.4

本版修正業務行動版修改密碼入口與手機快取問題：
- 登入後頂部新增「帳號設定」按鈕。
- 底部導覽新增明確「帳號設定」入口。
- 帳號設定使用正式表單修改密碼，不再使用瀏覽器 prompt。
- 必須輸入目前密碼、新密碼、再次確認。
- 修改成功後舊 Token 立即失效並要求重新登入。
- Sales session key 升級 v8_4。
- Service Worker 強制 updateViaCache:none，導覽頁採 no-store，啟用時清除舊 Cache。
- 保留 v8.3 全部密碼重設、Super Admin、SalesSafeSnapshot、成交防重複、取消成交、底薪獎金、利潤與操作紀錄功能。
