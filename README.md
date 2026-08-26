# FLOP Sentinel / Technocore local toolkit

FLOPテストネット公開前の準備と、FLOP関連情報の出典・主張を安全にローカル検査するためのツール群です。サイト全体の構想と実装計画は [construction.md](construction.md) にあります。

- 公開サイト: <https://lopital2023-max.github.io/flop-sentinel/>
- Source: <https://github.com/lopital2023-max/flop-sentinel>
- Security model: [THREAT_MODEL.md](THREAT_MODEL.md)

2026-08-27現在の状態です。

- ローカル環境: 構築済み
- 暗号・署名・nonce・送信処理のテスト: 公開fixture／mockで実施可能
- 公式情報の読み取り監視: 実施可能
- 公式rootとユーザー投稿領域の分類: 実装済み
- machine-readableな `public/status.json`: 生成可能
- URL・投稿・コントラクトアドレスのローカル検査: 実装済み
- Astro静的Webサイト（日英・5ページ）: 実装済み
- 公式source変更履歴 `public/changes.json`: 生成可能
- raw snapshot・JCS manifest hash-chain: **実装・初回生成済み**
- 既存DIDによるreviewed checkpoint: **Ed25519署名・検証済み**
- GitHub Pages・定期監視・公開API: **実装済み**
- 実運用Ed25519 DID: **発行済み**
- 公開DID note: **HTTP 200で公開済み**
- `lobby`への署名check-in: **HTTP 200で投稿済み**
- faucet／token claim: **未実施（endpoint自体が未公開）**

## 現在の公開ID

```text
DID: did:key:z6MkrPT8CW8EJhrRN5RZB4d3svmNgFtbrPx8sRWJpPQMZ1fu
Profile: https://technocore.chat/kv/did-7e/ae6cdae48a930c
Mailbox: mb-p-911c583d86b97feb1f8c60868b6f562d
Check-in room: lobby
Check-in nonce: 1787747616354
```

Technocoreには登録簿や登録endpointがないため、これは「中央登録」ではありません。公式conventionに従った公開DID noteと、そのDIDのprivate keyを保持していることを示す署名メッセージの組み合わせです。

Technocoreの現行認証仕様は、登録・claim・token endpointが存在しないと明記しています。そのため、このツールが現在監視・操作対象にするのはTechnocoreの通信層であり、FLOPチェーンやfaucetではありません。

## 必要環境

- Node.js 22.12以降の偶数系release（`.nvmrc`は22、検証環境は22.19.0）
- Astro 7.2.7（build時のdevDependency）

`.nvmrc` と `package-lock.json` で環境を固定しています。生成後の静的サイトにserver-side runtime依存関係はありません。最初に環境検査とローカルテストを実行します。

```bash
git clone https://github.com/lopital2023-max/flop-sentinel.git
cd flop-sentinel
nvm use
npm ci --ignore-scripts
npm run setup
npm test
npm run security:audit
```

VS Codeでは `Terminal` → `Run Task...` から以下を選べます。

- `FLOP: Run local tests`
- `FLOP: Check local environment`
- `FLOP: Check official sources`
- `FLOP: Build status.json`
- `FLOP: Start web development server`
- `FLOP: Build static website`

秘密鍵を偶発的に作らないよう、identity生成はVS Code taskに登録していません。

## 公式情報の監視

```bash
npm run monitor
```

監視対象は [config/sources.json](config/sources.json) の4 URLです。

1. `https://technocore.chat/openapi.json`
2. `https://technocore.chat/auth.md`
3. `https://flop.finance/`
4. `https://api.github.com/orgs/flop-labs/repos?...`

設定ファイルが書き換えられても任意URLを読みに行かないよう、同じURLをコード内でもallowlistに固定しています。公開roomは第三者の未検証入力なので監視しません。

初回はbaselineを作り、以後は次を検出します。

- Technocore OpenAPIのversion・path追加／削除
- `faucet`, `claim`, `token`, `wallet`, `rpc`, `inference`, `compute`, `testnet`を含む新規path
- Flop Labs GitHub組織のrepository追加／削除／更新
- 公式サイト・認証仕様の関連文言の変化
- 「claim/token endpointはない」という明示文の消失

ローカル出力は `.local/` に保存され、Gitから除外されます。

```text
.local/monitor-state.json     比較用baseline
.local/last-report.json       最新レポート
.local/monitor-history.jsonl  実行履歴
```

第3段階では、取得したexact bytesも `public/evidence/snapshots/` にSHA-256名で保存します。これらは公開検証用artifactであり、サイト自身はHTMLとして描画しません。GitHub Pages上では`.snapshot`が`application/octet-stream`として配信されることを実測していますが、custom response headerはPagesでは保証されません。

保存せず一度だけ確認する場合:

```bash
node src/cli.mjs monitor --no-write
```

## FLOP Sentinel 第一段階

### 公式root

[config/trust-roots.json](config/trust-roots.json) に、完全一致する公式ページ、公式GitHub namespace、公式サイトから参照されるXアカウントを分けて定義しています。

Technocoreの `/r/` と `/kv/` は公式ドメイン上にありますが、第三者が書き込めるため公式声明としては扱いません。この区別は、単なるdomain allowlistより優先されます。

### status.jsonの生成

保存済みの最新monitor reportから生成する場合:

```bash
npm run status:build
npm run status
```

公式4ソースを読み直してから生成する場合:

```bash
node src/cli.mjs status:build --refresh
```

出力は [public/status.json](public/status.json) です。各capabilityには状態、説明、根拠URL、観測日時、SHA-256が含まれます。「監視対象に未掲載」と「存在しない」を区別します。

### URL・投稿・アドレス検査

```bash
node src/cli.mjs check --input "https://flop.finance/"
node src/cli.mjs check --input "Claim at https://flop.finance.evil.example/claim" --json
node src/cli.mjs check --file suspicious-message.txt
```

標準入力も利用できます。

```bash
pbpaste | node src/cli.mjs check --json
```

検査対象URLをネットワークから取得することはありません。URL構造、固定したtrust root、`status.json`、秘密鍵要求などの文字列パターンだけを決定論的に検査します。主な判定は次の5種類です。

- `VERIFIED_OFFICIAL_ROOT`
- `OFFICIALLY_REFERENCED`
- `UNVERIFIED`
- `CONFLICTS_WITH_CURRENT_OFFICIAL_STATE`
- `HIGH_RISK_PATTERN`

この判定は安全保証や詐欺の法的断定ではありません。

## FLOP Sentinel 第二段階：Webサイト

日英切替に対応した次の5ページを実装しています。

- `/` — readiness dashboard、公式source graph、最新変更signal
- `/verify/` — URL・投稿・addressのブラウザ内検査と判定理由
- `/changes/` — SHA-256付きの変更履歴
- `/proof/` — snapshot、manifest連鎖、Ed25519署名のブラウザ内再検証
- `/methodology/` — 判定規則、信頼境界、限界

Web公開用データを生成します。

```bash
npm run web:data
```

公式4ソースを読み直す場合:

```bash
node src/cli.mjs web:data --refresh
```

開発serverと静的build:

```bash
npm run dev
npm run build
npm run verify:dist
```

build成果物は `dist/` に生成されます。`public/_headers`にはCSP、frame拒否、Permissions Policyなどの静的hosting向けheaderを定義しています。Astro telemetryは全scriptで無効化しています。

検証フォームは、同一originの `status.json` だけを読み込みます。入力したURLへのfetch、wallet接続、外部analytics、serverへのform送信はありません。

公開APIは以下です。GitHub Pages上ではすべて `/flop-sentinel/` 配下にあります。

- `status.json` — capability状態と根拠
- `changes.json` — 変更履歴
- `sources.json` — collector policy、trust root、snapshot参照
- `verdict-schema.json` — 判定結果のJSON Schema
- `proof.json` — 最新manifest／checkpointの発見情報
- `feed.xml` — Atom変更feed
- `llms.txt`、`.well-known/agent.json` — agent向け案内

## FLOP Sentinel 第三段階：署名付き証跡

公式sourceを再取得し、公開データを更新します。

```bash
node src/cli.mjs web:data --refresh
```

最新観測のraw bytesと派生JSONをmanifestへ固定します。JSONのhash対象はRFC 8785 JCSで正規化され、同一観測に対する再実行は既存manifestを再利用します。

```bash
npm run attest:manifest
```

内容をレビューした後だけ、既存DIDでcheckpointを署名します。この処理はKeychainからkeystore解除値をプロセス内へ一時的に読みますが、ネットワーク送信は行いません。

```bash
node src/cli.mjs attest:sign --acknowledge-reviewed-checkpoint
```

第三者検証と公開用`proof.json`の再生成:

```bash
npm run attest:verify
```

現在の初回証跡は次のとおりです。

```text
Manifest #1:    6431acfa5983253b757205a8c6a29bac2d5f9a7f93210ee2f0abd2929a57f450
Attestation #1: 604a4dd71c7f29b8943a3e51344aae61cc740b07cae4ee4efdb4052cf4c5d536
Reviewer DID:   did:key:z6MkrPT8CW8EJhrRN5RZB4d3svmNgFtbrPx8sRWJpPQMZ1fu
```

検証対象は、4つのraw snapshot、`status.json`、`changes.json`、trust root、monitor report、manifest chain、attestation chain、Ed25519署名です。これは観測後の完全性とDID鍵による承認を示しますが、FLOP公式認定、エアドロップ受給資格、オンチェーン証明ではありません。

## FLOP Sentinel 第四段階：GitHub公開

3つのGitHub Actions workflowを用意しています。

- `ci.yml` — review済みrefだけをread-only tokenで手動検証（外部fork PRは自動実行しない）
- `pages.yml` — `main`の検証済み静的artifactをGitHub Pagesへ配置
- `monitor.yml` — 毎日02:23 UTCに固定4ソースをGETし、公開証跡だけをcommit

workflowで使う公式Actionはすべて完全なcommit SHAへ固定しています。依存installは`npm ci --ignore-scripts`でlifecycle scriptを無効化します。scheduled monitorにkeystore、Keychain、DID private key、wallet情報は渡しません。そのため自動manifestは「観測済み」ですが「review署名済み」ではなく、`proof.json`と`/proof/`がこの差を表示します。

公開前後のローカル監査:

```bash
npm run security:audit
npm audit --audit-level=high
npm audit signatures
```

GitHub Pagesは任意response headerを設定できないため、`_headers`に加えて各HTMLへmeta CSPを埋め込んでいます。ただし`frame-ancestors`などresponse headerでのみ完全に効く制御にはhosting上の限界があります。詳細は [THREAT_MODEL.md](THREAT_MODEL.md) に明記しています。

## 秘密鍵管理

先に [SECURITY.md](SECURITY.md) を読んでください。Technocore用DIDは、暗号資産ウォレットとは別のEd25519鍵として作ります。既存ウォレットのseed/private keyは絶対に流用しません。

現在の実運用keystoreは `.local/identity.keystore.json` に`0600`で保存されています。中身はAES-256-GCMで暗号化され、KDFはscryptです。解除用のランダム32-byte値はmacOS Keychainの`flop-technocore-agent-keystore-v1`項目に保存され、ファイルや標準出力には出しません。

新しい別DIDを作る必要がある場合に限り、次のどちらかを使います。通常は同じDIDの継続性が重要なので、追加実行しません。

```bash
node src/cli.mjs identity:init --acknowledge-secret-generation
```

```bash
node src/cli.mjs identity:init-keychain \
  --acknowledge-secret-generation-and-keychain-storage
```

既存keystoreは上書きしません。

公開DIDだけを後から確認する場合:

```bash
node src/cli.mjs identity:show
```

## 外部投稿

次のコマンドは署名済みPOST bodyを表示するだけで、送信しません。

```bash
node src/cli.mjs say --room lobby --text "your message"
```

実際にTechnocoreへ投稿するには、末尾に明示フラグが必要です。

```bash
node src/cli.mjs say \
  --room lobby \
  --text "your message" \
  --execute-external-write
```

送信先は`https://technocore.chat`に固定しています。署名付きGET URLはアクセスログ等に残り、古いnonceの単回性にも限界があるため、送信にはJSON POSTだけを使います。

初回check-inは完了済みで、ローカルstateが二重check-inを拒否します。

## 構成

```text
flop/
├── .vscode/tasks.json
├── config/
│   ├── sources.json
│   └── trust-roots.json
├── public/
│   ├── .well-known/agent.json
│   ├── _headers
│   ├── changes.json
│   ├── proof.json
│   ├── evidence/
│   │   ├── snapshots/
│   │   ├── artifacts/
│   │   ├── manifests/
│   │   └── attestations/
│   ├── llms.txt
│   └── status.json
├── src/
│   ├── components/
│   ├── layouts/
│   ├── pages/
│   ├── styles/
│   ├── web/
│   ├── changes.mjs
│   ├── cli.mjs
│   ├── environment.mjs
│   ├── identity.mjs
│   ├── jcs.mjs
│   ├── evidence.mjs
│   ├── monitor.mjs
│   ├── nonce-store.mjs
│   ├── status.mjs
│   ├── verifier.mjs
│   ├── verify-dist.mjs
│   └── technocore.mjs
├── test/
├── construction.md
├── README.md
└── SECURITY.md
```

このツールは参加履歴やエアドロップ対象を保証しません。DID署名は鍵の所持を証明するだけで、人間の本人性・信用・将来のFLOPウォレットとの関連付けを証明しません。
