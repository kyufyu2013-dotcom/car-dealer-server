Server v8.3 / API 2.3.3

新增密碼管理：
1. 業務登入 /sales/ 後可修改自己的密碼（需輸入目前密碼）。
2. 車行管理員可重設自己車行內業務的密碼。
3. Super Admin 資料中心 /m200530366/ 的「全部帳號」可重設任一車行帳號密碼。
4. 車行管理員忘記帳號時，Super Admin 可在資料中心看到其帳號；忘記密碼則直接重設。
5. 密碼變更/重設後 token_version +1，舊登入 Token 立即失效，必須使用新密碼重新登入。
6. 密碼仍只存 scrypt 雜湊，不保存/顯示明碼舊密碼。
7. PostgreSQL 自動 migration：token_version / password_changed_at / password_changed_by。

保留 v8.2 全部功能、業務簡潔品牌登入頁、Super Admin 專屬入口。
