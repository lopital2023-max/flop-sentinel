# Contributing

FLOP Sentinelは非公式の安全ツールです。変更は「断定を増やす」より「根拠と限界を明確にする」方向を優先します。

## Pull request

1. Node.js 22を使用してください。
2. `npm ci --ignore-scripts`、`npm test`、`npm run build`、`npm run verify:dist`を実行してください。
3. 利用者入力や監視responseをshell、`eval`、HTMLとして実行する処理を追加しないでください。
4. 新しいnetwork接続先、dependency、GitHub Action、wallet連携は、脅威モデルとテストを同時に更新してください。
5. trust root変更は一次sourceの根拠を示し、管理者レビューを必要とします。

Pull requestのCIにはrepository write権限、DID private key、Keychain、deployment credentialを渡しません。

## 証跡

CIが作るmanifestは自動観測であり、review済み署名ではありません。Ed25519 reviewed checkpointは管理者がローカルで観測内容を確認した後、明示的に署名します。署名を要求するために秘密鍵やseedの提出を依頼してはいけません。
