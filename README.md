### 概要
Contrastサーバの監査ログを取得するツールです。CSV形式で出力することもできます。  
使用方法の詳細については [Release](https://github.com/Contrast-Security-OSS/AuditLogTool/releases) からダウンロードできるzipファイルに同梱のマニュアルpdfをご確認ください。


### 動作環境
Windows8.1、Windows10, Mac11(Big Sur)  
いずれも、jre1.8.0_202

### ソースからビルドする場合

ビルドからではなく、すぐにお使いいただく場合は[リリースについて](#リリースについて)を参照ください。


#### 環境にあわせてbuild.gradleの以下箇所を弄ってください。

- Windows 64bitの場合（java 64bitでEclipseなど動かしている場合はこのままで良いです）

  ```gradle
  compile group: 'org.eclipse.swt', name:   'org.eclipse.swt.win32.win32.x86_64', version: '4.3'
  //compile group: 'org.eclipse.swt', name: 'org.eclipse.swt.win32.win32.x86', version: '4.3'
  //compile group: 'org.eclipse.platform', name: 'org.eclipse.swt.cocoa.macosx.x86_64', version: '3.109.0', transitive: false
  ```
- Windows 32bitの場合（exeを作るために32bit版のビルドをする場合）

  ```gradle
  //compile group: 'org.eclipse.swt', name:   'org.eclipse.swt.win32.win32.x86_64', version: '4.3'
  compile group: 'org.eclipse.swt', name: 'org.eclipse.swt.win32.win32.x86', version: '4.3'
  //compile group: 'org.eclipse.platform', name: 'org.eclipse.swt.cocoa.macosx.x86_64', version: '3.109.0', transitive: false
  ```
- Macの場合

  ```gradle
  //compile group: 'org.eclipse.swt', name:   'org.eclipse.swt.win32.win32.x86_64', version: '4.3'
  //compile group: 'org.eclipse.swt', name: 'org.eclipse.swt.win32.win32.x86', version: '4.3'
  compile group: 'org.eclipse.platform', name: 'org.eclipse.swt.cocoa.macosx.x86_64', version: '3.109.0', transitive: false
  ```

#### コマンドプロンプト、ターミナルでビルドする場合

- Windows
  ```powershell
  gradlew clean jar
  ```
- Mac
  ```bash
  ./gradlew clean jar
  ```
build\libsの下にjarが作成されます。

#### Eclipseでビルド、実行できるようにする場合

- Windows
  ```powershell
  gradlew cleanEclipse eclipse
  ```
- Mac
  ```bash
  ./gradlew cleanEclipse eclipse
  ```
Eclipseでプロジェクトをリフレッシュすると、あとは実行でcom.contrastsecurity.auditlogtool.Mainで、ツールが起動します。

#### Windows配布用のexe化について

- launch4jを使っています。
- launch4j.xmlを読み込むと、ある程度設定が入っていて、あとはjar（ビルドによって作成された）やexeのパスを修正するぐらいです。
- jreがインストールされていない環境でも、jreフォルダを同梱することで環境に依存せずjavaを実行できるような設定になっています。  
  jreをDLして解凍したフォルダを **jre** というフォルダ名として置いておくと、優先して使用するような設定に既になっています。
- 32bit版Javaにしている理由ですが、今はもうないかもしれないですが、32bit版のwindowsの場合も想定してという感じです。

#### Mac配布用のapp化について

- javapackagerを使っています。
- jreを同梱させるため、実施するMacに1.8.0_202のJREフォルダを任意の場所に配置しておいてください。
- jarpackage.sh内の3〜7行目を適宜、修正してください。
- jarpackage.shを実行します。
  ```bash
  ./jarpackage.sh
  ```
  build/libs/bundle下にappフォルダが作られます。

#### exe, appへの署名について

まず、証明書ファイル(pfx)と証明書パスワードを入手してください。  
署名についは以下の手順で実行してください。  
- Windows  
  - エイリアスの確認
    ```powershell
    keytool -list -v -storetype pkcs12 -keystore C:\Users\turbou\Desktop\AuditLogTool_work\XXXXX.pfx
    # 証明書パスワードを入力
    ```
  - 署名  
    launch4jのsign4jを使用します。
    ```powershell
    cd C:\Program Files (x86)\launch4j\sign4j
    sign4j.exe java -jar jsign-2.0.jar --alias 1 --keystore C:\Users\turbou\Desktop\AuditLogTool_work\XXXXX.pfx --storepass [パスワード] C:\Users\turbou\Desktop\AuditLogTool_work\common\AuditLogTool_1.0.3.exe
    ```
  - 署名の確認  
    署名の確認については、exeを右クリック->プロパティ で確認できます。
- Mac
  - 証明書ファイルの読み込み  
    pfxファイルをダブルクリックでキーチェーンアクセス.appに読み込ませます。証明書パスワード入力が必要  
    読み込めたら、Common Name(通称)をコピー
  - 署名
    ```bash
    codesign --deep -s "Contrast Security, Inc." -v AuditLogTool_1.0.3.app
    ```
  - 署名の確認
    ```bash
    codesign -d --verbose=4 AuditLogTool_1.0.3.app
    ```
    
#### 圧縮について補足

- Mac
  ```bash
  7z a AuditLogTool_1.0.3.cli7z AuditLogTool_1.0.3.app/
  ```

### 起動後の使い方について

- 設定画面で、TeamServerのURL、ユーザ名、サービスキーを個人のものに変更してください。  
  **Admin権限を持つユーザー、またはSuperAdminユーザーを設定してください。**  
- Admin権限ユーザーの場合は組織情報の追加ボタンで組織を追加してください。  
  **SuperAdminユーザーの場合は組織の追加は不要です。**  
  組織は複数登録が可能です。監査ログを取得する対象の組織にチェックを入れてください。  
  ※ 必要に応じて、プロキシ設定も行っておいてください。
- 設定を閉じて、監査ログを取得します。  
  適宜、取得期間を選んでください。  
- 右クリックメニューから選択済みの監査ログをCSVエクスポートすることもできます。  
  全選択はCtrl + A または右クリックメニューから可能です。

使用方法の詳細については [Release](https://github.com/Contrast-Security-OSS/AuditLogTool/releases) からダウンロードできるzipファイルに同梱のマニュアルpdfをご確認ください。

### リリースについて
[Release](https://github.com/Contrast-Security-OSS/AuditLogTool/releases) で以下3種類のバイナリを提供しています。ビルド不要でダウンロード後すぐにお使いいただけます。
- Windows
  - AuditLogTool_X.X.X.zip  
    初回ダウンロードの場合はこちらをダウンロードして解凍して、お使いください。  
    jreフォルダ（1.8.0_202）が同梱されているため、exeの起動ですぐにツールを使用できます。
  - AuditLogTool_X.X.X.exe  
    既にzipをダウンロード済みの場合はexeのダウンロードと入れ替えのみでツールを使用できます。
- Mac
  - AuditLogTool_X.X.X.cli7z  
    下記コマンドで解凍してください。  
    ```bash
    # p7zipのインストールについては
    brew install p7zip
    # 解凍コマンド
    7z x AuditLogTool_X.X.X.cli7z
    ```

以上
