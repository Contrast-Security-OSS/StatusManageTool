package com.contrastsecurity.statusmanagetool;

import org.eclipse.jface.dialogs.ProgressMonitorDialog;
import org.eclipse.swt.widgets.Shell;

public class PendingStatusApprovalProgressMonitorDialog extends ProgressMonitorDialog {

    public PendingStatusApprovalProgressMonitorDialog(Shell parent) {
        super(parent);
    }

    @Override
    protected void configureShell(Shell newShell) {
        super.configureShell(newShell);
        newShell.setText("保留中ステータス更新");
    }

}
