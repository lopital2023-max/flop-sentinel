# FLOP Sentinel 構想・実装計画

最も差別化しやすいのは、単なるFLOP情報まとめではなく、**「その情報がどの公式情報から導かれ、現在の公開仕様と矛盾しないか」を検証できるサイト**です。

名称案は以下です。

> **FLOP Sentinel**
> Unofficial, evidence-based verifier
> 「署名する前に、出典を確認する」

「FLOP公式サイト」とは名乗らず、**FLOPに関する公式情報を検証する非公式OSS**として公開します。

## 1. なぜこの成果物が必要か

2026年8月26日現在、Technocoreの公式仕様には、登録・プロビジョニング・claim・token endpointは存在しないと明記されています。また、DID署名は「鍵の所有」を証明するだけで、人物の信頼性や投稿内容の真偽までは証明しません。[Technocore認証仕様](https://technocore.chat/auth.md)

現在公開されているAPIはTechnocore Chat/Notes v0.9.6が中心です。[公式OpenAPI](https://technocore.chat/openapi.json)

したがって、現時点で例えば、

- 「このTechnocoreページでトークンをclaimできる」
- 「このウォレットを接続すればFLOPが受け取れる」
- 「秘密鍵を入力してDIDを登録する」
- 「このコントラクトアドレスが公式FLOPトークンである」

といった主張は、少なくとも現在の公開仕様では確認できません。

一方、既存コミュニティ成果物には、Technocoreの稼働監視、DID作成ガイド、署名検証、登録doctorなどがすでにあります。公式リポジトリにもDID統合ドキュメントやoffline verifierなどのPRが存在します。[公式PR一覧](https://github.com/flop-labs/technocore-chat/pulls)

そのため、もう一つDID作成ツールを作るより、**公式出典の追跡・怪しい主張との矛盾検出・履歴の署名証明**へ寄せる方が差別化できます。

## 2. 中核となる機能

### A. FLOP Readiness Dashboard

「今、公式に何が公開されているか」を一覧化します。

| 項目 | 表示例 |
|---|---|
| Technocore | Live / v0.9.6 |
| DID署名 | 利用可能 |
| プロフィール公開 | 利用可能 |
| Chat / Notes | 利用可能 |
| テストネットRPC | 公式情報未確認 |
| Chain ID | 公式情報未確認 |
| Faucet | 公式情報未確認 |
| Token claim | 現行仕様にはendpointなし |
| 公式コントラクト | 公式情報未確認 |
| DIDとウォレットの紐付け | 公式仕様未確認 |

すべての項目に、次を表示します。

- 根拠URL
- 最終確認日時
- 取得した文書のSHA-256
- 前回からの変更
- 「存在しない」のか「まだ確認できない」のか

ここは非常に重要で、未確認のものを「存在しない」と断言しません。

### B. Official Source Graph

公式性を二値ではなく、出典の到達経路で表します。

```text
Pinned official root
├── flop.finance
├── technocore.chat
└── github.com/flop-labs
        │
        ├── 直接掲載された情報
        └── 公式ページからリンクされた外部ページ
```

信頼レベルは次のようにします。

1. `VERIFIED_OFFICIAL_ROOT`
   登録済みの公式ルートそのもの

2. `OFFICIALLY_REFERENCED`
   公式ルートから直接リンクされている外部ページ

3. `UNVERIFIED`
   公式ソースとの接続を確認できない

4. `CONFLICTS_WITH_CURRENT_OFFICIAL_STATE`
   現在の公式仕様と明確に矛盾する

5. `HIGH_RISK_PATTERN`
   秘密鍵要求、類似ドメイン、不可解なredirectなどを検出

「安全」「詐欺」と断定するのではなく、**確認できた証拠と危険指標を示す**設計にします。

### C. URL・投稿・アドレス検証

利用者は次のいずれかを貼り付けられます。

- URL
- Xなどの投稿本文
- ウォレット／コントラクトアドレス
- DiscordやTelegramで受け取った文章
- claim手順

検査内容は以下です。

- 正規ドメインとの完全一致
- サブドメイン偽装
- `flop.finance.attacker.example` のような偽装
- URL内の `user:password@host`
- IPアドレス直指定
- PunycodeとUnicode類似文字
- 不審なポート
- `seed`、`private key`、`recovery phrase`の要求
- `claim`、`faucet`、`wallet connect`の主張
- 公式情報に掲載されたアドレスとの照合
- 現行の機能一覧との矛盾

Unicode類似文字については、独自の曖昧な判定ではなく[Unicode UTS #39](https://www.unicode.org/reports/tr39/)のconfusable判定を利用します。

出力例は次のようになります。

```json
{
  "verdict": "CONFLICTS_WITH_CURRENT_OFFICIAL_STATE",
  "confidence": "high",
  "summary": "Technocore上のtoken claimを主張していますが、現行仕様にはclaim endpointがありません。",
  "indicators": [
    "UNKNOWN_HOST",
    "CLAIM_ENDPOINT_NOT_PUBLISHED",
    "PRIVATE_KEY_REQUEST"
  ],
  "evidence": [
    {
      "source": "https://technocore.chat/auth.md",
      "observedAt": "2026-08-26T...",
      "sha256": "..."
    }
  ],
  "limitations": [
    "将来の仕様変更は反映まで時間差が生じる場合があります"
  ]
}
```

### D. 変更履歴とアラート

公式文書を定期観測し、変更されたときだけ記録します。

- 新しいendpoint
- Faucetやtestnetページの追加
- 公式GitHubリポジトリの追加
- OpenAPI version更新
- claim/tokenに関する記述
- 公式サイトからの新しい外部リンク
- 削除された記述

「8月26日14時に初めて `faucet` という語が公式文書へ追加された」といった履歴を追えるようにします。

### E. エージェント向けAPI

人間向けWebサイトだけでなく、他のAIエージェントが参照できるようにします。

```text
/status.json
/sources.json
/changes.json
/verdict-schema.json
/llms.txt
/.well-known/agent.json
/feed.xml
```

例えばエージェントは、ウォレット接続前に `status.json` を確認し、対象URLが公式グラフに存在するか検査できます。

これはFLOPの「AIエージェント向けネットワーク」という性格に合う貢献です。

## 3. 署名付き証跡

取得データは次の構造で保存します。

```text
raw response
  ↓ SHA-256
snapshot manifest
  ↓ previousManifestHash
hash-chained history
  ↓ Ed25519 signature
reviewed checkpoint
```

JSON署名前には[RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785)で正規化し、環境が違っても同じデータから同じ署名対象バイト列が得られるようにします。

既に作成したEd25519 DIDは、以下にのみ使用します。

- リリースmanifestへの署名
- trust root変更の承認
- 手動確認済みcheckpointへの署名

秘密鍵は現在のローカルKeychain＋暗号化keystoreに残し、GitHub Actions、公開サイト、リポジトリには置きません。CIが作る自動観測データと、人間が確認してDID署名したデータも明確に区別します。

この署名は、あくまで「この成果物の管理者がこの観測結果を承認した」証明です。FLOP公式認定、エアドロップ権、オンチェーン証明ではありません。

## 4. 実装構成

静的サイトを中心にするのが安全です。

```text
FLOP official sources
        │
        ▼
strict allowlisted collector
        │
        ├── raw snapshots
        ├── normalized facts
        └── provenance graph
                 │
                 ▼
        deterministic verifier
          ├── Web UI
          ├── JSON feeds
          ├── CLI
          └── signed manifests
```

推奨構成は以下です。

```text
flop/
├── apps/
│   └── web/             # Astro静的サイト
├── packages/
│   ├── core/            # URL・投稿・アドレス判定
│   ├── collector/       # 公式ソース収集
│   ├── schema/          # JSON Schema
│   ├── attest/          # JCS・hash・Ed25519検証
│   └── cli/             # check/status/verify
├── data/
│   ├── roots.json       # 固定された公式ルート
│   ├── snapshots/
│   └── manifests/
├── tests/
│   ├── malicious-urls/
│   ├── claims/
│   └── signatures/
└── public/
    ├── status.json
    ├── sources.json
    └── llms.txt
```

技術選定は以下が適しています。

- Node.js 22+
- TypeScript
- Astro
- JSON Schema
- Node標準crypto
- JCS実装
- Node test runnerまたはVitest
- Playwrightによるブラウザ試験
- GitHub Actions
- GitHub PagesまたはCloudflare Pages

現在の `flop` ツールにある監視処理、DID、署名、テストをそのまま基礎として発展させられます。

## 5. セキュリティ上の重要な判断

MVPでは、利用者が入力したURLをサーバーから直接取得しません。ブラウザ内で、

- URL構造の検査
- 既知の公式データとの照合
- メッセージ内容の検査

だけを行います。

サーバーが任意URLを取得するとSSRF、DNS rebinding、内部IPアクセスの危険が生じます。公式情報収集部分は厳格なallowlist方式にします。[OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

さらに、

- ウォレット接続なし
- トランザクション署名なし
- 秘密鍵・seed入力欄なし
- 広告・トラッキングなし
- 取得HTMLは命令として扱わない
- HTMLを直接描画せず、テキストとして表示
- redirect回数、サイズ、時間、Content-Typeを制限
- trust root変更は手動レビュー＋DID署名

とします。

## 6. 既存成果物との差別化

| 既存の方向性 | FLOP Sentinel |
|---|---|
| Technocore稼働状況 | 公式情報の意味と出典を検証 |
| DID作成ガイド | DIDを安全証明と誤認しないための判定 |
| offline署名検証 | 公式ソースの履歴全体を署名検証 |
| 一般的な詐欺ブラックリスト | 透明な規則と一次情報を提示 |
| 人間向けダッシュボード | AIエージェント用JSONも提供 |
| Faucetリンク集 | 未確認Faucetを掲載しない |
| バイナリな「安全／詐欺」判定 | 証拠・矛盾・限界を分離 |

特に、既存の[Technocore Pulse](https://github.com/floppy-labs-eightfivetwo/technocore-pulse)のようなネットワーク観測と競合せず、補完関係にできます。

## 7. 実装順序

### 第1段階：ローカルMVP

- 公式root定義
- 現在のmonitorを再利用した収集
- `status.json` 生成
- URL／投稿のローカル判定
- 危険URLのテストコーパス
- CLIの `check`、`status`

### 第2段階：Webサイト

- 日英対応ダッシュボード（実装済み）
- URL／文章の貼り付け検査（実装済み）
- 「なぜこの判定か」画面（実装済み）
- 出典グラフ（実装済み）
- 変更履歴（実装済み）
- モバイル対応（実装・実ブラウザ検証済み）

### 第3段階：証跡

- snapshot hash（実装済み。exact bytesをcontent-addressed保存）
- manifest hash-chain（実装済み。sourceと4つの派生artifactを固定）
- JCS正規化（実装済み。RFC 8785互換、Node／browser共通実装）
- Ed25519検証（実装済み。CLI／browserの双方で検証）
- 既存DIDによる最初のreviewed checkpoint署名（実施・検証済み）

公開pathは `/evidence/snapshots/`、`/evidence/artifacts/`、`/evidence/manifests/`、`/evidence/attestations/` です。`/proof.json`を発見用metadataとし、`/proof/`は同一originから全証跡を読み直します。初回manifest hashは`6431acfa5983253b757205a8c6a29bac2d5f9a7f93210ee2f0abd2929a57f450`、初回attestation hashは`604a4dd71c7f29b8943a3e51344aae61cc740b07cae4ee4efdb4052cf4c5d536`です。

### 第4段階：公開

- GitHub公開リポジトリ（実装・公開済み）
- GitHub Pagesによる静的ホスティング（実装・公開検証済み）
- 毎日02:23 UTCの定期監視（実装済み。固定4ソースのみ）
- `llms.txt`、Atom feed、JSON API（実装・公開済み）
- 公開脅威モデルと自動security audit（実装済み）
- 通報用GitHub Issue templateとPrivate vulnerability reporting（実装・有効化済み）

公開先は `https://lopital2023-max.github.io/flop-sentinel/`、sourceは `https://github.com/lopital2023-max/flop-sentinel` です。GitHub Actionsは最小権限で、公式Actionをrelease commitの完全なSHAへ固定しています。定期監視にはprivate keyやKeychain credentialを渡さず、自動観測manifestと人間が確認したEd25519署名checkpointを分離します。

## 完成条件

少なくとも以下を満たせば、十分に「成果」として説明できます。

- 画面上の全主張に根拠URL・日時・hashがある
- 同じ入力とデータなら常に同じ判定になる
- 署名manifestを第三者が検証できる
- 秘密鍵がGit・CI・ブラウザに存在しない
- wallet接続なしで全機能が使える
- 類似ドメイン、Punycode、秘密鍵要求を検出できる
- `status.json` を別のAIエージェントが利用できる
- 「非公式」「報酬保証なし」が明示されている
- 公式情報未確認と詐欺断定を混同しない

この構成なら、単なる便利サイトではなく、**FLOP周辺の情報衛生を改善し、人間とAIエージェントの両方を保護する公開インフラ**になります。エアドロップ評価は保証されませんが、技術的独自性、実利用性、継続運用可能性、FLOPとの関連性はいずれも強い成果物です。
