package com.contrastsecurity.statusmanagetool;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jface.preference.PreferenceStore;
import org.eclipse.swt.SWT;
import org.eclipse.swt.custom.CTabFolder;
import org.eclipse.swt.custom.CTabItem;
import org.eclipse.swt.graphics.Font;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Label;

public class VulSubDetailTabItem extends CTabItem implements PropertyChangeListener {

    private PreferenceStore ps;

    Logger logger = LogManager.getLogger("vulnstatusmanagetool");

    public VulSubDetailTabItem(CTabFolder subTabFolder, VulnStatusManageToolShell toolShell, PreferenceStore ps) {
        super(subTabFolder, SWT.NONE);
        this.ps = ps;
        setText("詳細");

        Composite shell = new Composite(subTabFolder, SWT.NONE);
        shell.setLayout(new GridLayout(1, false));
        Label createGroupDescLbl = new Label(shell, SWT.LEFT);
        GridData createGroupDescLblGrDt = new GridData();
        createGroupDescLblGrDt.horizontalSpan = 3;
        createGroupDescLbl.setLayoutData(createGroupDescLblGrDt);
        createGroupDescLbl.setFont(new Font(shell.getDisplay(), "Arial", 11, SWT.NORMAL));
        List<String> strList = new ArrayList<String>();
        strList.add("現在、実装中です。");
        createGroupDescLbl.setText(String.join("\r\n", strList));

        setControl(shell);
    }

    private void uiReset() {
    }

    @Override
    public void propertyChange(PropertyChangeEvent event) {
        if ("selectedTraceChanged".equals(event.getPropertyName())) {
        } else if ("uiReset".equals(event.getPropertyName())) {
            uiReset();
        }
    }

}
