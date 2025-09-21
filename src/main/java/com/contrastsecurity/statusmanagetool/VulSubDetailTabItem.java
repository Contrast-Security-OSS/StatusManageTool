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
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Text;

import com.contrastsecurity.statusmanagetool.model.EventDetail;
import com.contrastsecurity.statusmanagetool.model.ItemForVulnerability;

public class VulSubDetailTabItem extends CTabItem implements PropertyChangeListener {

    private PreferenceStore ps;
    private Text text;

    private static final String STACK_TRACE = "==================== 詳細 ====================";

    Logger logger = LogManager.getLogger("vulnstatusmanagetool");

    public VulSubDetailTabItem(CTabFolder subTabFolder, VulnStatusManageToolShell toolShell, PreferenceStore ps) {
        super(subTabFolder, SWT.NONE);
        this.ps = ps;
        setText("詳細");

        Composite shell = new Composite(subTabFolder, SWT.NONE);
        shell.setLayout(new GridLayout(1, false));

        this.text = new Text(shell, SWT.MULTI | SWT.WRAP | SWT.BORDER | SWT.V_SCROLL);
        GridData textGrDt = new GridData(GridData.FILL_BOTH);
        this.text.setLayoutData(textGrDt);
        this.text.setText("");
        this.text.setEditable(false);

        setControl(shell);
    }

    private void uiReset() {
    }

    @Override
    public void propertyChange(PropertyChangeEvent event) {
        if ("selectedTraceChanged".equals(event.getPropertyName())) {
            List<String> strList = new ArrayList<String>();
            strList.add(STACK_TRACE);
            ItemForVulnerability selectedVul = (ItemForVulnerability) event.getNewValue();
            for (EventDetail ed : selectedVul.getVulnerability().getEventDetails()) {
                strList.addAll(ed.getDetailLines());
            }
            this.text.setText(String.join("\r\n", strList));
        } else if ("uiReset".equals(event.getPropertyName())) {
            uiReset();
        }
    }

}
