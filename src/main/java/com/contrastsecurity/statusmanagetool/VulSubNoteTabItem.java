package com.contrastsecurity.statusmanagetool;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jface.preference.PreferenceStore;
import org.eclipse.swt.SWT;
import org.eclipse.swt.custom.CTabFolder;
import org.eclipse.swt.custom.CTabItem;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Table;
import org.eclipse.swt.widgets.TableColumn;
import org.eclipse.swt.widgets.TableItem;

import com.contrastsecurity.statusmanagetool.model.ItemForVulnerability;
import com.contrastsecurity.statusmanagetool.model.Note;

public class VulSubNoteTabItem extends CTabItem implements PropertyChangeListener {

    private PreferenceStore ps;
    private Table noteTable;

    Logger logger = LogManager.getLogger("vulnstatusmanagetool");

    public VulSubNoteTabItem(CTabFolder subTabFolder, VulnStatusManageToolShell toolShell, PreferenceStore ps) {
        super(subTabFolder, SWT.NONE);
        this.ps = ps;
        setText("アクティビティ");

        Composite shell = new Composite(subTabFolder, SWT.NONE);
        shell.setLayout(new GridLayout(1, false));

        noteTable = new Table(shell, SWT.BORDER | SWT.FULL_SELECTION | SWT.MULTI);
        GridData noteTableGrDt = new GridData(GridData.FILL_BOTH);
        noteTableGrDt.horizontalSpan = 3;
        // noteTableGrDt.minimumHeight = 100;
        // noteTableGrDt.heightHint = 150;
        noteTable.setLayoutData(noteTableGrDt);
        noteTable.setLinesVisible(true);
        noteTable.setHeaderVisible(true);

        TableColumn noteCol0 = new TableColumn(noteTable, SWT.NONE);
        noteCol0.setWidth(0);
        noteCol0.setResizable(false);
        TableColumn noteCol1 = new TableColumn(noteTable, SWT.CENTER);
        noteCol1.setWidth(150);
        noteCol1.setText("作成日時");
        TableColumn noteCol2 = new TableColumn(noteTable, SWT.CENTER);
        noteCol2.setWidth(200);
        noteCol2.setText("作成者");
        TableColumn noteCol3 = new TableColumn(noteTable, SWT.CENTER);
        noteCol3.setWidth(100);
        noteCol3.setText("承認処理");
        TableColumn noteCol4 = new TableColumn(noteTable, SWT.LEFT);
        noteCol4.setWidth(500);
        noteCol4.setText("コメント");
        TableColumn noteCol5 = new TableColumn(noteTable, SWT.CENTER);
        noteCol5.setWidth(100);
        noteCol5.setText("変更前ステータス");
        TableColumn noteCol6 = new TableColumn(noteTable, SWT.CENTER);
        noteCol6.setWidth(100);
        noteCol6.setText("変更後ステータス");
        TableColumn noteCol7 = new TableColumn(noteTable, SWT.CENTER);
        noteCol7.setWidth(150);
        noteCol7.setText("変更理由");

        setControl(shell);
    }

    private void addColToNoteTable(Note note, int index) {
        if (note == null) {
            return;
        }
        TableItem item = new TableItem(noteTable, SWT.CENTER);
        item.setText(1, note.getCreationStr());
        item.setText(2, note.getCreator());
        String resolutionStr = note.getProperty("pending.status.resolution");
        if (!resolutionStr.isEmpty()) {
            if (Boolean.valueOf(resolutionStr)) {
                item.setText(3, "○");
            } else {
                item.setText(3, "×");
            }
        } else {
            item.setText(3, "");
        }
        item.setText(4, note.getNote());
        item.setText(5, note.getProperty("status.change.previous.status"));
        item.setText(6, note.getProperty("status.change.status"));
        item.setText(7, note.getProperty("status.change.substatus"));
    }

    private void uiReset() {
        noteTable.clearAll();
        noteTable.removeAll();
    }

    @Override
    public void propertyChange(PropertyChangeEvent event) {
        if ("selectedTraceChanged".equals(event.getPropertyName())) {
            noteTable.clearAll();
            noteTable.removeAll();
            ItemForVulnerability selectedVul = (ItemForVulnerability) event.getNewValue();
            for (Note note : selectedVul.getVulnerability().getNotes()) {
                addColToNoteTable(note, -1);
            }
        } else if ("uiReset".equals(event.getPropertyName())) {
            uiReset();
        }
    }
}
