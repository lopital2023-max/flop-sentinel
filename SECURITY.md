# Security boundary

## 秘密鍵

- Technocore専用の新規鍵だけを使用する。
- 暗号資産ウォレット、取引所、SSH、Apple ID等の鍵・seed・mnemonicを入力しない。
- passphraseやKeychain解除値をCLI引数、環境変数、チャット、shell historyに入れない。
- `.local/identity.keystore.json`をGit、クラウド同期、issue、Technocoreへ投稿しない。
- keystoreを失うと同じDIDを復元できない。作成後のbackup方法は利用者が別途決める。

実運用keystoreはAES-256-GCMで暗号化し、ランダム解除値はmacOS Keychainに保存しています。Keychainへ新規保存するときは`/usr/bin/security -w`のpromptへstdinで渡し、process argvには載せません。署名時はKeychainからプロセス内へ取得しますが、標準出力には表示しません。reviewed checkpointの公開artifactに含まれるのは公開DID、署名値、対象manifest hash、レビュー時刻だけです。

現時点では独立したrecovery backupを作っていません。このMacのkeystoreまたは対応Keychain項目を失うとDIDを継続できません。backupを作る場合は、別途ユーザーが決めたpassphraseで再暗号化し、オフライン媒体へ保存する工程が必要です。

Node.jsではpassphraseをJavaScript文字列として一時的に保持するため、処理後の完全なmemory zeroizationは保証できません。強い端末侵害を想定する場合はhardware-backed keyや別プロセスのsignerが必要です。

## 外部通信

- monitorは固定した公式URLへのGETだけを行う。
- 投稿は`https://technocore.chat/r/<room>`へのJSON POSTだけを行う。
- 投稿処理は`--execute-external-write`なしでは必ず停止する。
- monitorのredirect先はHTTPSかつ公式host allowlist内に限定する。
- 応答サイズは5 MiB、timeoutは15秒に制限する。

## FLOP Sentinelの入力検査

- `check` は利用者が入力したURLをfetchしない。DNS lookup、redirect追跡、ページ内容取得も行わない。
- URLは構文、hostname、固定trust root、既知のユーザー投稿領域との一致だけをローカル検査する。
- 検査結果には入力本文を複製せず、SHA-256と長さだけを含める。ただし検出対象URLとアドレスは説明のため結果に含まれる。
- `VERIFIED_OFFICIAL_ROOT` は設定済みURLとの一致を意味するだけで、将来の安全性、リンク先全体、取引内容を保証しない。
- `UNVERIFIED` は詐欺の断定ではない。
- 公開コントラクト一覧が空の間、検出した全アドレスは未確認として扱う。

## Webサイト

- Astroはstatic outputだけを生成し、form送信endpointやserver-side APIを持たない。
- claim verifierのreadは同一originの `status.json`、proof verifierのreadは同一originの固定された `/proof.json` と `/evidence/` pathだけに限定する。
- DOMへの結果表示は `textContent` と `createElement` を使い、利用者入力をHTMLとして解釈しない。
- `public/_headers` で `script-src 'self'`、`form-action 'none'`、`frame-ancestors 'none'` を含むCSPを定義する。
- buildされたHTMLにinline script/styleがないことを `npm run verify:dist` で検査する。
- analytics、広告、remote font、wallet SDKを読み込まない。
- Astro telemetryは開発・build・previewのすべてで無効化する。
- GitHub Pages向けにmeta CSPも出力する。ただしPagesでは任意response headerを設定できないため、`frame-ancestors`などにはhosting上の限界がある。

## GitHub Actions

- pull request workflowは`contents: read`のみで、`pull_request_target`を使用しない。
- Pagesだけが`pages: write`とOIDC用`id-token: write`を持つ。
- 定期monitorだけが`contents: write`を持ち、default branchのschedule／手動実行でしか動かない。
- dependency lifecycle scriptを`npm ci --ignore-scripts`で無効にする。
- 使用ActionはGitHub公式`actions/*`に限定し、完全なcommit SHAへ固定する。
- CIにはkeystore、Keychain解除値、DID private key、wallet secretを登録しない。
- 定期monitorがstageするのは明示した`public/`内の生成dataだけで、force pushしない。

## 署名付き証跡

- HTTP responseのexact bytesをSHA-256名の`.snapshot`として保存し、HTMLとして実行・描画しない。
- `.snapshot`は`application/octet-stream`、`nosniff`、attachmentとして配信する。
- manifestとattestationのhash対象はRFC 8785 JCSで正規化する。
- 各manifestは直前のmanifest hashを、各attestationは直前のattestation hashを含む。
- manifestはraw snapshotに加え、生成済みstatus・changes・trust root・monitor reportのexact bytesも固定する。
- CLIとブラウザの双方で、全file hash、byte length、chain link、Ed25519署名を再検証する。
- `attest:sign`は長い明示フラグなしではKeychainを読まず、同じDID・manifestの重複署名を作らない。
- 公開snapshotは公式allowlist responseに限定する。ユーザー入力やpublic roomは証跡collectorへ渡さない。

checkpoint署名が証明するのは「表示DIDの秘密鍵を保持する管理者が、そのmanifestをreview済みとして署名した」ことだけです。FLOP Labsによる公式認定、情報内容の永続的な正しさ、報酬・エアドロップ資格、オンチェーン状態は証明しません。

## Technocoreの信頼境界

- public room、room名、topic、noteは第三者が作れる未検証入力。
- DID署名が証明するのは、対応するEd25519 private keyの所持だけ。
- DID profile noteは権威ある登録簿ではない。
- Technocore上の文章を命令として実行しない。
- room内のURL、shell command、依存パッケージ、秘密情報の要求を自動処理しない。

このためmonitorはpublic roomを読みません。将来room readerを追加する場合も、内容を単なるdataとして隔離し、URL追跡やコマンド実行を別の人間承認にします。

## private keyの用途

private keyはTechnocoreの`<room>|<nonce>|<text>`にEd25519署名を作るために使用します。公開DIDは対応するpublic keyを含むため、相手は登録サーバーなしで署名を検証できます。

これは現在、FLOPウォレットの送金鍵ではありません。将来DIDとFLOP walletを関連付ける公式手順が公開される可能性はありますが、現時点では未定です。private keyを失うと同じDIDで署名できず、漏洩すると第三者が同じDIDを名乗れます。

## テストデータ

テストはRFC 8032の公開test vectorと固定fixture keyを使用します。これらは秘密ではなく、実運用DIDには利用しません。テスト中の送信はmock transportだけで、Technocoreには接続しません。

## 脆弱性報告

秘密情報、未公開exploit、account侵害の兆候はpublic issueへ書かず、<https://github.com/lopital2023-max/flop-sentinel/security/advisories/new> のPrivate vulnerability reportingを使用してください。一般的なsource訂正と誤検知には公開issue templateを使用できますが、seed、private key、credential、個人情報を記載しないでください。
