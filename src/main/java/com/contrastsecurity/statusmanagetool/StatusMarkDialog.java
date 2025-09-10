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

import java.util.ArrayList;
import java.util.List;

import org.eclipse.jface.dialogs.Dialog;
import org.eclipse.jface.dialogs.IDialogConstants;
import org.eclipse.jface.preference.IPreferenceStore;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.ModifyEvent;
import org.eclipse.swt.events.ModifyListener;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.events.TraverseEvent;
import org.eclipse.swt.events.TraverseListener;
import org.eclipse.swt.graphics.Point;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Combo;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Text;

import com.contrastsecurity.statusmanagetool.model.Organization;
import com.contrastsecurity.statusmanagetool.model.SubStatusOTAlias;

public class StatusMarkDialog extends Dialog {

    private IPreferenceStore ps;
    private VulnStatusManageToolShell toolShell;
    private List<Organization> orgs;
    private int selectedStatusIndex;
    private Combo subStatusCombo;
    private int selectedSubStatusIndex;
    private Label descLbl;
    private Text noteText;
    private String note;

    public StatusMarkDialog(VulnStatusManageToolShell parentShell, IPreferenceStore ps, List<Organization> orgs) {
        super(parentShell);
        this.toolShell = parentShell;
        this.ps = ps;
        this.orgs = orgs;
    }

    @Override
    protected Control createDialogArea(Composite parent) {
        Composite composite = (Composite) super.createDialogArea(parent);
        composite.setLayout(new GridLayout(4, false));

        new Label(composite, SWT.LEFT).setText("ステータス:");
        Combo statusCombo = new Combo(composite, SWT.DROP_DOWN | SWT.READ_ONLY);
        GridData statusComboGrDt = new GridData(GridData.FILL_HORIZONTAL);
        statusCombo.setLayoutData(statusComboGrDt);
        // statusCombo.add("選択...");
        this.selectedStatusIndex = 0;
        for (StatusEnum statusEnum : StatusEnum.comboValues()) {
            statusCombo.add(statusEnum.getLabel());
        }
        statusCombo.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent event) {
                Combo combo = (Combo) event.getSource();
                selectedStatusIndex = combo.getSelectionIndex();
                okPressBtnUpdate();
            }
        });

        new Label(composite, SWT.LEFT).setText("理由:");
        subStatusCombo = new Combo(composite, SWT.DROP_DOWN | SWT.READ_ONLY);
        GridData subStatusComboGrDt = new GridData(GridData.FILL_HORIZONTAL);
        subStatusCombo.setLayoutData(subStatusComboGrDt);
        subStatusCombo.setEnabled(false);
        // subStatusCombo.add("選択...");
        this.selectedSubStatusIndex = 0;
        for (SubStatusEnum subStatusEnum : SubStatusEnum.values()) {
            subStatusCombo.add(subStatusEnum.getLabel());
        }
        subStatusCombo.select(0);
        subStatusCombo.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent event) {
                Combo combo = (Combo) event.getSource();
                selectedSubStatusIndex = combo.getSelectionIndex();
                okPressBtnUpdate();
            }
        });
        List<String> aliasList = new ArrayList<String>();
        for (Organization org : this.orgs) {
            SubStatusOTAlias alias = this.toolShell.getMain().getOrgOTAliasMap().get(org.getOrganization_uuid());
            if (alias != null) {
                aliasList.add(String.format("%s: %s", org.getName(), alias.getLabel()));
            }
        }
        if (!aliasList.isEmpty()) {
            aliasList.add(0, "理由の「その他」に関しては、各組織ごとに別ラベルが設定されている場合があります。別ラベルについては以下参照ください。");
        }
        subStatusCombo.setToolTipText(String.join("\r\n", aliasList));

        descLbl = new Label(composite, SWT.LEFT);
        GridData descLblGrDt = new GridData(GridData.FILL_HORIZONTAL);
        descLblGrDt.horizontalSpan = 4;
        descLbl.setLayoutData(descLblGrDt);
        descLbl.setText("説明:");
        noteText = new Text(composite, SWT.MULTI | SWT.BORDER | SWT.WRAP | SWT.V_SCROLL);
        GridData textGrDt = new GridData(GridData.FILL_BOTH);
        textGrDt.horizontalSpan = 4;
        noteText.setLayoutData(textGrDt);
        noteText.addTraverseListener(new TraverseListener() {
            @Override
            public void keyTraversed(TraverseEvent event) {
                if (event.detail == SWT.TRAVERSE_TAB_NEXT) {
                    event.doit = true;
                } else {
                    event.doit = false;
                }
            }
        });
        noteText.addModifyListener(new ModifyListener() {
            @Override
            public void modifyText(ModifyEvent event) {
                Text text = (Text) event.getSource();
                note = text.getText();
                okPressBtnUpdate();
            }
        });

        return composite;
    }

    private void okPressBtnUpdate() {
        StatusEnum selectedStatus = getStatus();
        if (selectedStatus.isRequiredSubStatus()) {
            subStatusCombo.setEnabled(true);
            SubStatusEnum selectedSubStatus = getSubStatus();
            if (selectedSubStatus.isRequiredNote()) {
                descLbl.setText("根拠（必須）:");
                if (noteText.getText().isEmpty()) {
                    getButton(IDialogConstants.OK_ID).setEnabled(false);
                } else {
                    getButton(IDialogConstants.OK_ID).setEnabled(true);
                }
            } else {
                descLbl.setText("根拠:");
                getButton(IDialogConstants.OK_ID).setEnabled(true);
            }
        } else {
            subStatusCombo.setEnabled(false);
            descLbl.setText("説明:");
            if (noteText.getText().isEmpty()) {
                getButton(IDialogConstants.OK_ID).setEnabled(false);
            } else {
                getButton(IDialogConstants.OK_ID).setEnabled(true);
            }
        }
    }

    public StatusEnum getStatus() {
        return StatusEnum.values()[this.selectedStatusIndex];
    }

    public SubStatusEnum getSubStatus() {
        return SubStatusEnum.values()[this.selectedSubStatusIndex];
    }

    public String getNote() {
        return this.note;
    }

    @Override
    protected void createButtonsForButtonBar(Composite parent) {
        Button okButton = createButton(parent, IDialogConstants.OK_ID, IDialogConstants.OK_LABEL, true);
        okButton.setEnabled(false);
        createButton(parent, IDialogConstants.CANCEL_ID, IDialogConstants.CANCEL_LABEL, false);
    }

    @Override
    protected void okPressed() {
        super.okPressed();
    }

    @Override
    protected Point getInitialSize() {
        return new Point(480, 520);
    }

    @Override
    protected void setShellStyle(int newShellStyle) {
        super.setShellStyle(SWT.CLOSE | SWT.TITLE | SWT.RESIZE | SWT.APPLICATION_MODAL);
    }

    @Override
    protected void configureShell(Shell newShell) {
        super.configureShell(newShell);
        newShell.setText("ステータス更新");
    }
}
