/*
 * MIT License
 * Copyright (c) 2025 Contrast Security Japan G.K.
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 */

package com.contrastsecurity.statusmanagetool;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.commons.exec.OS;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jface.dialogs.IDialogConstants;
import org.eclipse.jface.preference.PreferenceDialog;
import org.eclipse.jface.preference.PreferenceManager;
import org.eclipse.jface.preference.PreferenceNode;
import org.eclipse.jface.preference.PreferenceStore;
import org.eclipse.jface.window.Window;
import org.eclipse.swt.SWT;
import org.eclipse.swt.custom.CTabFolder;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.events.ShellEvent;
import org.eclipse.swt.events.ShellListener;
import org.eclipse.swt.graphics.Color;
import org.eclipse.swt.graphics.Font;
import org.eclipse.swt.graphics.Image;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Label;

import com.contrastsecurity.statusmanagetool.api.Api;
import com.contrastsecurity.statusmanagetool.api.LogoutApi;
import com.contrastsecurity.statusmanagetool.model.Organization;
import com.contrastsecurity.statusmanagetool.preference.AboutPage;
import com.contrastsecurity.statusmanagetool.preference.BasePreferencePage;
import com.contrastsecurity.statusmanagetool.preference.ConnectionPreferencePage;
import com.contrastsecurity.statusmanagetool.preference.MyPreferenceDialog;
import com.contrastsecurity.statusmanagetool.preference.OtherPreferencePage;
import com.contrastsecurity.statusmanagetool.preference.PreferenceConstants;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;

import okhttp3.CookieJar;

public class Main implements PropertyChangeListener {

    public static final String WINDOW_TITLE = "StatusManageTool - %s";
    // 以下のMASTER_PASSWORDはプロキシパスワードを保存する際に暗号化で使用するパスワードです。
    // 本ツールをリリース用にコンパイルする際はchangeme!を別の文字列に置き換えてください。
    public static final String MASTER_PASSWORD = "changeme!";

    // 各出力ファイルの文字コード
    public static final String CSV_WIN_ENCODING = "Shift_JIS";
    public static final String CSV_MAC_ENCODING = "UTF-8";
    public static final String FILE_ENCODING = "UTF-8";

    public static final int MINIMUM_SIZE_WIDTH = 800;
    public static final int MINIMUM_SIZE_WIDTH_MAC = 880;
    public static final int MINIMUM_SIZE_HEIGHT = 640;

    private VulnStatusManageToolShell shell;

    private CTabFolder mainTabFolder;

    private Button settingBtn;
    private Button logOutBtn;

    private Label statusBar;

    private PreferenceStore ps;
    private List<Organization> orgsForSuperAdminOpe;

    private PropertyChangeSupport support = new PropertyChangeSupport(this);
    private CookieJar cookieJar;

    public enum AuthType {
        TOKEN,
        PASSWORD
    }

    Logger logger = LogManager.getLogger("vulnstatusmanagetool");

    private AuthType authType;

    /**
     * @param args
     */
    public static void main(String[] args) {
        Main main = new Main();
        main.authType = AuthType.TOKEN;
        if (System.getProperty("auth") != null && System.getProperty("auth").equals("password")) {
            main.authType = AuthType.PASSWORD;
        }
        main.initialize();
        main.createPart();
    }

    public AuthType getAuthType() {
        return authType;
    }

    public void setCookieJar(CookieJar cookieJar) {
        this.cookieJar = cookieJar;
    }

    public CookieJar getCookieJar() {
        return this.cookieJar;
    }

    private void initialize() {
        try {
            String homeDir = System.getProperty("user.home");
            this.ps = new PreferenceStore(homeDir + "\\statusmanagetool.properties");
            if (OS.isFamilyMac()) {
                this.ps = new PreferenceStore(homeDir + "/statusmanagetool.properties");
            }
            try {
                this.ps.load();
            } catch (FileNotFoundException fnfe) {
                this.ps = new PreferenceStore("statusmanagetool.properties");
                this.ps.load();
            }
        } catch (FileNotFoundException fnfe) {
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            this.ps.setDefault(PreferenceConstants.IS_SUPERADMIN, "false");
            this.ps.setDefault(PreferenceConstants.IS_CREATEGROUP, "false");
            this.ps.setDefault(PreferenceConstants.GROUP_NAME, "StatusManageToolGroup");
            this.ps.setDefault(PreferenceConstants.BASIC_AUTH_STATUS, BasicAuthStatusEnum.NONE.name());
            this.ps.setDefault(PreferenceConstants.PASS_TYPE, "input");
            this.ps.setDefault(PreferenceConstants.TSV_STATUS, TsvStatusEnum.NONE.name());
            this.ps.setDefault(PreferenceConstants.PROXY_AUTH, "none");
            this.ps.setDefault(PreferenceConstants.CONNECTION_TIMEOUT, 3000);
            this.ps.setDefault(PreferenceConstants.SOCKET_TIMEOUT, 3000);
            this.ps.setDefault(PreferenceConstants.AUTO_RELOGIN_INTERVAL, 105);
            this.ps.setDefault(PreferenceConstants.AUTH_RETRY_MAX, 3);

            this.ps.setDefault(PreferenceConstants.VULN_CHOICE, VulnTypeEnum.ALL.name());
            this.ps.setDefault(PreferenceConstants.DETECT_CHOICE, "FIRST");
            this.ps.setDefault(PreferenceConstants.TERM_START_MONTH, "Jan");
            this.ps.setDefault(PreferenceConstants.START_WEEKDAY, 1); // 月曜日
            this.ps.setDefault(PreferenceConstants.TRACE_DETECTED_DATE_FILTER, 0);

            this.ps.setDefault(PreferenceConstants.OPENED_MAIN_TAB_IDX, 0);
            if (this.authType == AuthType.PASSWORD) {
                this.ps.setValue(PreferenceConstants.SERVICE_KEY, "");
            }
        } catch (Exception e) {
            // e.printStackTrace();
        }
    }

    private void createPart() {
        Display display = new Display();
        shell = new VulnStatusManageToolShell(display, this);
        if (OS.isFamilyMac()) {
            shell.setMinimumSize(MINIMUM_SIZE_WIDTH_MAC, MINIMUM_SIZE_HEIGHT);
        } else {
            shell.setMinimumSize(MINIMUM_SIZE_WIDTH, MINIMUM_SIZE_HEIGHT);
        }
        Image[] imageArray = new Image[5];
        imageArray[0] = new Image(display, Main.class.getClassLoader().getResourceAsStream("icon16.png"));
        imageArray[1] = new Image(display, Main.class.getClassLoader().getResourceAsStream("icon24.png"));
        imageArray[2] = new Image(display, Main.class.getClassLoader().getResourceAsStream("icon32.png"));
        imageArray[3] = new Image(display, Main.class.getClassLoader().getResourceAsStream("icon48.png"));
        imageArray[4] = new Image(display, Main.class.getClassLoader().getResourceAsStream("icon128.png"));
        shell.setImages(imageArray);
        Window.setDefaultImages(imageArray);
        setWindowTitle();
        shell.addShellListener(new ShellListener() {
            @Override
            public void shellIconified(ShellEvent event) {
            }

            @Override
            public void shellDeiconified(ShellEvent event) {
            }

            @Override
            public void shellDeactivated(ShellEvent event) {
            }

            @Override
            public void shellClosed(ShellEvent event) {
                int main_idx = mainTabFolder.getSelectionIndex();
                ps.setValue(PreferenceConstants.OPENED_MAIN_TAB_IDX, main_idx);
                ps.setValue(PreferenceConstants.MEM_WIDTH, shell.getSize().x);
                ps.setValue(PreferenceConstants.MEM_HEIGHT, shell.getSize().y);
                ps.setValue(PreferenceConstants.PROXY_TMP_USER, "");
                ps.setValue(PreferenceConstants.PROXY_TMP_PASS, "");
                support.firePropertyChange("shellClosed", null, null);
                try {
                    ps.save();
                } catch (IOException ioe) {
                    ioe.printStackTrace();
                }
            }

            @Override
            public void shellActivated(ShellEvent event) {
                boolean ngRequiredFields = false;
                String url = ps.getString(PreferenceConstants.CONTRAST_URL);
                String usr = ps.getString(PreferenceConstants.USERNAME);
                if (authType == AuthType.PASSWORD) {
                    if (url.isEmpty() || usr.isEmpty()) {
                        ngRequiredFields = true;
                    }
                } else {
                    String svc = ps.getString(PreferenceConstants.SERVICE_KEY);
                    if (url.isEmpty() || usr.isEmpty() || svc.isEmpty()) {
                        ngRequiredFields = true;
                    }
                }
                boolean isSuperAdmin = ps.getBoolean(PreferenceConstants.IS_SUPERADMIN);
                String svc = ps.getString(PreferenceConstants.SERVICE_KEY);
                if (isSuperAdmin) {
                    String api = ps.getString(PreferenceConstants.API_KEY);
                    if (url.isEmpty() || usr.isEmpty() || svc.isEmpty() || api.isEmpty()) {
                        ngRequiredFields = true;
                    }
                } else {
                    if (url.isEmpty() || usr.isEmpty() || svc.isEmpty()) {
                        ngRequiredFields = true;
                    }
                }
                List<Organization> orgs = getValidOrganizations();
                if (ngRequiredFields || (!isSuperAdmin && orgs.isEmpty())) {
                    support.firePropertyChange("buttonEnabled", null, false);
                    support.firePropertyChange("validOrgChanged", null, null);
                    settingBtn.setText("このボタンから基本設定を行ってください。");
                } else {
                    support.firePropertyChange("buttonEnabled", null, true);
                    settingBtn.setText("設定");
                }
                setWindowTitle();
                if (ps.getBoolean(PreferenceConstants.PROXY_YUKO) && ps.getString(PreferenceConstants.PROXY_AUTH).equals("input")) {
                    String proxy_usr = ps.getString(PreferenceConstants.PROXY_TMP_USER);
                    String proxy_pwd = ps.getString(PreferenceConstants.PROXY_TMP_PASS);
                    if (proxy_usr == null || proxy_usr.isEmpty() || proxy_pwd == null || proxy_pwd.isEmpty()) {
                        ProxyAuthDialog proxyAuthDialog = new ProxyAuthDialog(shell);
                        int result = proxyAuthDialog.open();
                        if (IDialogConstants.CANCEL_ID == result) {
                            ps.setValue(PreferenceConstants.PROXY_AUTH, "none");
                        } else {
                            ps.setValue(PreferenceConstants.PROXY_TMP_USER, proxyAuthDialog.getUsername());
                            ps.setValue(PreferenceConstants.PROXY_TMP_PASS, proxyAuthDialog.getPassword());
                        }
                    }
                }
            }
        });

        GridLayout baseLayout = new GridLayout(1, false);
        baseLayout.marginWidth = 8;
        baseLayout.marginBottom = 0;
        baseLayout.verticalSpacing = 8;
        shell.setLayout(baseLayout);

        mainTabFolder = new CTabFolder(shell, SWT.NONE);
        GridData mainTabFolderGrDt = new GridData(GridData.FILL_BOTH);
        mainTabFolder.setLayoutData(mainTabFolderGrDt);
        mainTabFolder.setSelectionBackground(new Color[] { display.getSystemColor(SWT.COLOR_WIDGET_BACKGROUND), display.getSystemColor(SWT.COLOR_WIDGET_LIGHT_SHADOW) },
                new int[] { 100 }, true);
        mainTabFolder.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                support.firePropertyChange("tabSelected", null, mainTabFolder.getSelection()); //$NON-NLS-1$
            }
        });

        addPropertyChangeListener(new VulTabItem(mainTabFolder, shell, ps));

        int main_idx = this.ps.getInt(PreferenceConstants.OPENED_MAIN_TAB_IDX);
        mainTabFolder.setSelection(main_idx);

        Composite bottomBtnGrp = new Composite(shell, SWT.NONE);
        GridLayout bottomBtnGrpLt = new GridLayout();
        if (this.authType == AuthType.PASSWORD) {
            bottomBtnGrpLt.numColumns = 2;
        } else {
            bottomBtnGrpLt.numColumns = 1;
        }
        bottomBtnGrpLt.makeColumnsEqualWidth = false;
        bottomBtnGrpLt.marginHeight = 0;
        bottomBtnGrp.setLayout(bottomBtnGrpLt);
        GridData bottomBtnGrpGrDt = new GridData(GridData.FILL_HORIZONTAL);
        bottomBtnGrp.setLayoutData(bottomBtnGrpGrDt);

        // ========== 設定ボタン ==========
        settingBtn = new Button(bottomBtnGrp, SWT.PUSH);
        settingBtn.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
        settingBtn.setText("設定");
        settingBtn.setToolTipText("動作に必要な設定を行います。");
        settingBtn.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent event) {
                PreferenceManager mgr = new PreferenceManager();
                PreferenceNode baseNode = new PreferenceNode("base", new BasePreferencePage(shell, authType));
                PreferenceNode connectionNode = new PreferenceNode("connection", new ConnectionPreferencePage(authType));
                PreferenceNode otherNode = new PreferenceNode("other", new OtherPreferencePage());
                mgr.addToRoot(baseNode);
                mgr.addToRoot(connectionNode);
                mgr.addToRoot(otherNode);
                PreferenceNode aboutNode = new PreferenceNode("about", new AboutPage());
                mgr.addToRoot(aboutNode);
                PreferenceDialog dialog = new MyPreferenceDialog(shell, mgr);
                dialog.setPreferenceStore(ps);
                dialog.open();
                try {
                    ps.save();
                } catch (IOException ioe) {
                    ioe.printStackTrace();
                }
            }
        });

        // ========== ログアウトボタン ==========
        if (this.authType == AuthType.PASSWORD) {
            this.logOutBtn = new Button(bottomBtnGrp, SWT.PUSH);
            this.logOutBtn.setLayoutData(new GridData());
            this.logOutBtn.setText("ログアウト");
            this.logOutBtn.setToolTipText("認証済みセッションからログアウトします。");
            this.logOutBtn.setEnabled(false);
            this.logOutBtn.addSelectionListener(new SelectionAdapter() {
                @Override
                public void widgetSelected(SelectionEvent event) {
                    logOut();
                }
            });
        }

        this.statusBar = new Label(shell, SWT.RIGHT);
        GridData statusBarGrDt = new GridData(GridData.FILL_HORIZONTAL);
        statusBarGrDt.minimumHeight = 11;
        statusBarGrDt.heightHint = 11;
        this.statusBar.setLayoutData(statusBarGrDt);
        this.statusBar.setFont(new Font(display, "ＭＳ ゴシック", 9, SWT.NORMAL));
        this.statusBar.setForeground(shell.getDisplay().getSystemColor(SWT.COLOR_DARK_GRAY));

        uiUpdate();
        int width = this.ps.getInt(PreferenceConstants.MEM_WIDTH);
        int height = this.ps.getInt(PreferenceConstants.MEM_HEIGHT);
        if (width > 0 && height > 0) {
            shell.setSize(width, height);
        } else {
            shell.setSize(MINIMUM_SIZE_WIDTH, MINIMUM_SIZE_HEIGHT);
            // shell.pack();
        }
        shell.open();
        try {
            while (!shell.isDisposed()) {
                if (!display.readAndDispatch()) {
                    display.sleep();
                }
            }
        } catch (Exception e) {
            StringWriter stringWriter = new StringWriter();
            PrintWriter printWriter = new PrintWriter(stringWriter);
            e.printStackTrace(printWriter);
            String trace = stringWriter.toString();
            logger.error(trace);
        }
        display.dispose();
    }

    public void loggedIn() {
        String timestamp = new SimpleDateFormat("yyyy/MM/dd HH:mm").format(new Date()); //$NON-NLS-1$
        String userName = ps.getString(PreferenceConstants.USERNAME);
        this.statusBar.setText(String.format("%s %s successfully logged in", userName, timestamp)); //$NON-NLS-1$
        this.logOutBtn.setEnabled(true);
    }

    public void logOut() {
        Api logoutApi = new LogoutApi(shell, ps, getValidOrganization());
        try {
            logoutApi.getWithoutCheckTsv();
        } catch (Exception e) {
            e.printStackTrace();
        }
        loggedOut();
    }

    public void loggedOut() {
        this.cookieJar = null;
        this.statusBar.setText(""); //$NON-NLS-1$
        ps.setValue(PreferenceConstants.XSRF_TOKEN, ""); //$NON-NLS-1$
        ps.setValue(PreferenceConstants.BASIC_AUTH_STATUS, BasicAuthStatusEnum.NONE.name());
        ps.setValue(PreferenceConstants.TSV_STATUS, TsvStatusEnum.NONE.name());
        logOutBtn.setEnabled(false);
    }

    public void setOrgsForSuperAdminOpe(List<Organization> orgsForSuperAdminOpe) {
        this.orgsForSuperAdminOpe = orgsForSuperAdminOpe;
    }

    public Organization getValidOrganization() {
        if (ps.getBoolean(PreferenceConstants.IS_SUPERADMIN)) {
            Organization orgForSuperAdmin = new Organization();
            orgForSuperAdmin.setName("SuperAdmin");
            orgForSuperAdmin.setOrganization_uuid(this.ps.getString(PreferenceConstants.ORG_ID));
            orgForSuperAdmin.setApikey(this.ps.getString(PreferenceConstants.API_KEY));
            return orgForSuperAdmin;
        }
        String orgJsonStr = ps.getString(PreferenceConstants.TARGET_ORGS);
        if (orgJsonStr.trim().length() > 0) {
            try {
                List<Organization> orgList = new Gson().fromJson(orgJsonStr, new TypeToken<List<Organization>>() {
                }.getType());
                for (Organization org : orgList) {
                    if (org != null && org.isValid()) {
                        return org;
                    }
                }
            } catch (JsonSyntaxException e) {
                return null;
            }
        }
        return null;
    }

    public List<Organization> getValidOrganizations() {
        List<Organization> orgs = new ArrayList<Organization>();
        if (ps.getBoolean(PreferenceConstants.IS_SUPERADMIN) && this.orgsForSuperAdminOpe != null) {
            for (Organization org : this.orgsForSuperAdminOpe) {
                orgs.add(org);
            }
        }
        String orgJsonStr = ps.getString(PreferenceConstants.TARGET_ORGS);
        if (orgJsonStr.trim().length() > 0) {
            try {
                List<Organization> orgList = new Gson().fromJson(orgJsonStr, new TypeToken<List<Organization>>() {
                }.getType());
                for (Organization org : orgList) {
                    if (org != null && org.isValid()) {
                        orgs.add(org);
                    }
                }
            } catch (JsonSyntaxException e) {
                return orgs;
            }
        }
        return orgs;
    }

    public PreferenceStore getPreferenceStore() {
        return ps;
    }

    public void setWindowTitle() {
        String text = null;
        List<Organization> validOrgs = getValidOrganizations();
        if (validOrgs != null && !validOrgs.isEmpty()) {
            List<String> orgNameList = new ArrayList<String>();
            for (Organization validOrg : validOrgs) {
                orgNameList.add(validOrg.getName());
            }
            text = String.join(", ", orgNameList);
        }
        boolean isSuperAdmin = ps.getBoolean(PreferenceConstants.IS_SUPERADMIN);
        if (isSuperAdmin) {
            this.shell.setText(String.format(WINDOW_TITLE, "SuperAdmin"));
        } else {
            if (text == null || text.isEmpty()) {
                this.shell.setText(String.format(WINDOW_TITLE, "組織未設定"));
            } else {
                this.shell.setText(String.format(WINDOW_TITLE, text));
            }
        }
    }

    private void uiUpdate() {
    }

    @SuppressWarnings("unchecked")
    @Override
    public void propertyChange(PropertyChangeEvent event) {
        if ("tsv".equals(event.getPropertyName())) {
            System.out.println("tsv main");
        }
    }

    /**
     * @param listener
     */
    public synchronized void addPropertyChangeListener(PropertyChangeListener listener) {
        this.support.addPropertyChangeListener(listener);
    }

    /**
     * @param listener
     */
    public synchronized void removePropertyChangeListener(PropertyChangeListener listener) {
        this.support.removePropertyChangeListener(listener);
    }
}
