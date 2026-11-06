# dots-kick-events — dots を MCP Events で起こす発火側サーバー

dots（ChatGPT／一姫）を、OpenAI 公式ガイド「MCP Events」の仕組みで直接起こすための、イベント発火側 MCP サーバー。Cloudflare Worker として実装・デプロイ済み。

- 公式ガイド: https://developers.openai.com/plugins/build/mcp-events
- 本番 MCP エンドポイント: `https://dots-events.0g0.xyz/mcp`
- workers.dev: `https://dots-kick-events.0g0.workers.dev/mcp`（サブドメイン有効。ただしこの VM からは workers.dev への POST がタイムアウトする環境要因があるため、検証はカスタムドメインで実施）
- 実装: [worker.js](sandbox://workspace/dots-kick-events/worker.js)（単一ファイル、依存なし）

## 構成

- Cloudflare Worker `dots-kick-events`（アカウント 0g0）
- 永続化は **Durable Object（SQLite、クラス `Store`、単一インスタンス）に集約**。当初計画の KV は、現在の Cloudflare 接続（OAuth）の権限に KV／D1 が含まれず作成・読み取りとも 403 になったため、Workers プラットフォーム内蔵の DO に切り替えた。購読・依頼はすべて DO 内に保存され、再デプロイでも消えない。
- デプロイは Cloudflare コネクタの `execute`（API 直叩き）で行った。`wrangler.toml` はデプロイ済み構成の写し（参照用）。

## 実装したプロトコル（ガイド準拠）

MCP エンドポイント `POST /mcp`（JSON-RPC 2.0）:

| メソッド | 内容 |
|---|---|
| `initialize` | `capabilities` に `tools` と `events` を広告（Streamable HTTP） |
| `server/discover` | MCP 2.0（`2026-07-28`）向けに `resultType:"complete"`、`supportedVersions:["2026-07-28"]`、`events` 能力を返却 |
| `events/list` | イベント定義を返却（下記 `kick` 1種） |
| `events/subscribe` | 購読の作成／更新。署名付きチャレンジでコールバックを検証してから保存 |
| `events/unsubscribe` | 名前・引数・コールバックURLが一致する購読を停止（冪等、空の結果を返却） |
| `tools/list` / `tools/call` | 照合用ツール2種（下記） |

### イベント `kick`

- `delivery: ["webhook"]` のみ（ガイド通り、polling／streaming と `gap`・`terminated` 制御通知は ChatGPT 統合が非サポートのため実装しない）
- 購読引数（フィルタ）: `topic`（任意の文字列。一致する topic の依頼だけ配送）
- ペイロード `data`: `request_id`、`text`、`topic`（任意）、`created_at`

### 購読（events/subscribe）の処理

1. イベント名・引数を定義と照合。未知のフィルタ引数は `-32602`。
2. `delivery.secret` が `whsec_` 形式で Base64 デコード後 24–64 バイトであることを検証。
3. コールバックURLは HTTPS 必須。localhost／プライベートIPリテラル等を拒否（拒否時は `-32015`）。
4. 購読IDは principal（現状は固定値 `anonymous`、後述）＋コールバックURL＋イベント名＋引数の canonical JSON から決定的に導出。同一IDなら更新（冪等）。
5. 保存前に、署名付きの検証リクエスト `{"type":"verification","challenge":...}` をコールバックへ送り、2xx かつチャレンジの一致を確認。失敗時は JSON-RPC エラー `-32015`（`data.reason`: `challenge_failed` / `timeout` など）。検証成功は principal＋URL 単位で24時間キャッシュし、再購読時の再チャレンジを省略。
6. 有効期限: `ttlMs` 省略時は7日、`ttlMs` 指定時は最小1時間・最大30日にクランプ、`ttlMs: null`（無期限要求）でも有限の期限を返す。結果に `refreshBefore` を含める（`cursor: null`、`truncated: false`）。
7. 秘密鍵ローテーション時（再購読で新しい secret が来た場合）は旧鍵を10分間保持し、その間は新旧両方の署名をスペース区切りで付ける（Standard Webhooks の作法）。

### 配送（Webhook）

- 依頼1件につき購読ごとに1リクエスト。ボディは `{eventId, name:"kick", timestamp, data, cursor:null}`、256 KiB 以下。
- ヘッダ: `webhook-id`（= `eventId`）、`webhook-timestamp`（Unix秒）、`webhook-signature`（Standard Webhooks の HMAC-SHA256、`v1,...`）、`X-MCP-Subscription-Id`。
- `eventId` は依頼ID＋購読IDから決定的に生成され、リトライでも不変（dots 側の重複排除に使える）。
- 一時失敗は最大3回まで指数バックオフで再試行（410／413 は再試行しない）。リダイレクトは追従しない（Workers の fetch は `redirect:"error"` 非対応のため `"manual"` にし、2xx 以外を失敗として扱うことで等価にしている）。

### 照合用ツール

| ツール | 内容 |
|---|---|
| `list_pending_requests` | 未完了（completed 以外）の依頼を新しい順に返す。引数 `limit`（任意、既定20） |
| `update_request_status` | 依頼を `acknowledged`（受領）または `completed`（完了）に更新。冪等。引数 `request_id`、`status`、`note`（任意） |

### 依頼の状態

`pending`（保存済み・未配送または配送失敗）→ `delivered`（Webhook が 2xx で受領）→ `acknowledged`（dots が受領を申告）→ `completed`（dots が完了を申告）。配送結果（購読ごと・試行回数・HTTP状態）は依頼レコードに残るので、未完了分は `list_pending_requests` で後から照合できる。

## 発火方法（管理用）

`POST /trigger` に管理キーで依頼テキストを送ると、依頼を保存し、アクティブな全購読へ即配送する。

```bash
KEY=$(cat ~/workspace/goals/reason-network/hidden_files/dots-events-trigger-key.txt)
curl -X POST https://dots-events.0g0.xyz/trigger \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $KEY" \
  -d '{"text":"依頼の本文","topic":"任意のトピック"}'
```

- 管理キーは Worker のシークレット `TRIGGER_KEY` と上記ファイルにのみ保存（値はこの README やログには書かない）。
- レスポンスは `request_id`、状態、一致した購読数、配送成功数、購読ごとの結果（秘密情報は含まない）。

## dots 側の接続手順（未実施・dots 側の操作待ち）

ガイドの手順に沿って dots／ユーザーが実施する:

1. プラグインとしてこの MCP サーバー（`https://dots-events.0g0.xyz/mcp`）を接続する。
2. MCP を再スキャンし、ツール2種とイベント `kick` がプラグイン画面に並ぶことを確認する。
3. Work チャット（または dots）で、`kick` イベントの購読と、届いたときの処理（例：依頼内容を確認し、`list_pending_requests` で照合して、着手時に `update_request_status` で `acknowledged`、終わったら `completed` を返す）を指示する。
4. こちらから `/trigger` でテスト依頼を送り、dots が起きて反応することを確認する。

## 検証結果（2026-11-06 実施済み）

- `initialize` / `server/discover` / `events/list` / `tools/list` がガイドの例示どおりの形で返ることを curl で確認。
- 署名アルゴリズムは Standard Webhooks 公式テストベクタと完全一致を事前確認。
- 署名を検証する独立エコー（別 Worker、検証後に削除済み）を使い、購読→チャレンジ検証→発火→署名付き配送（200）→`acknowledged`→`completed`→解除→配送停止、までの全ライフサイクルを実地で確認。
- 異常系も確認：管理キーなし発火 401／secret 形式不正 `-32602`／未知イベント `-32602`／http コールバック `-32015 (not_https)`／到達不能コールバック `-32015 (challenge_failed)`。
- 本番構成（テスト用変数を除いた最終ビルド）でもヘルス・各メソッド・発火（購読0件）のスモークテストを実施済み。ストレージには自己検証の完了済み依頼レコードが3件残っている（未完了一覧には出ない）。

## 制限・未確認事項

- **認証（OAuth）は未実装**で、MCP エンドポイントは現状オープン。購読IDの principal は固定値 `anonymous`。ChatGPT のプラグイン接続が OAuth ディスカバリ等を要求する場合、接続時に追加実装が必要になる可能性がある（ガイド本文だけでは未確認）。実運用前に認証の追加を検討すること。
- **購読と実配信の dots 側テストは未実施**（上記「接続手順」は dots 側の操作が必要なため）。ここまでで確認できているのはサーバー側の仕様準拠と自己検証まで。
- SSRF 対策は「HTTPS 必須＋プライベートIPリテラル等の拒否」まで。ガイドが求める「名前解決して検証済みアドレスへ接続」は Workers の fetch では実現できず、部分準拠。
- Worker から自分自身の URL への fetch は Cloudflare の制限で失敗する（自己検証で確認）。実運用のコールバックは ChatGPT 側の URL なので影響しない。
- イベントの replay（cursor）は非対応：`cursor` は常に `null`。配送断の間に起きた依頼はプロトコル上は復旧できないが、依頼レコード自体は残るため `list_pending_requests` で照合して拾える。
- テスト用に `worker.js` 内に `POST /test-echo`（`TEST_ECHO=1` のときだけ有効な署名検証エコー）と、その使い捨てフィクスチャ [echo-test-worker.js](sandbox://workspace/dots-kick-events/echo-test-worker.js) が残っている。本番では `TEST_ECHO` を設定していないため無効（404 を確認済み）。
