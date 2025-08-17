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

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.eclipse.jface.dialogs.Dialog;
import org.eclipse.jface.dialogs.IDialogConstants;
import org.eclipse.jface.viewers.ArrayContentProvider;
import org.eclipse.jface.viewers.CheckStateChangedEvent;
import org.eclipse.jface.viewers.CheckboxTableViewer;
import org.eclipse.jface.viewers.ColumnLabelProvider;
import org.eclipse.jface.viewers.ICheckStateListener;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.MouseAdapter;
import org.eclipse.swt.events.MouseEvent;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.graphics.Point;
import org.eclipse.swt.graphics.Rectangle;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Group;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Table;
import org.eclipse.swt.widgets.TableItem;

import com.contrastsecurity.statusmanagetool.model.Filter;

public class TraceFilterDialog extends Dialog {

    private Map<FilterEnum, Set<Filter>> filterMap;
    private Map<FilterEnum, CheckboxTableViewer> treeViewerMap;
    private PropertyChangeSupport support = new PropertyChangeSupport(this);

    public TraceFilterDialog(Shell parentShell, Map<FilterEnum, Set<Filter>> filterMap) {
        super(parentShell);
        this.filterMap = filterMap;
        this.treeViewerMap = new HashMap<FilterEnum, CheckboxTableViewer>();
    }

    @Override
    protected Control createDialogArea(Composite parent) {
        Composite composite = (Composite) super.createDialogArea(parent);
        GridLayout compositeLt = new GridLayout(3, false);
        compositeLt.marginWidth = 25;
        compositeLt.marginHeight = 5;
        compositeLt.horizontalSpacing = 5;
        composite.setLayout(compositeLt);
        GridData compositeGrDt = new GridData(GridData.FILL_BOTH);
        composite.setLayoutData(compositeGrDt);

        for (FilterEnum filterEnum : FilterEnum.values()) {
            Group filterGrp = new Group(composite, SWT.NONE);
            GridLayout filterGrpLt = new GridLayout(1, false);
            filterGrpLt.marginWidth = 10;
            filterGrpLt.marginHeight = 10;
            filterGrp.setLayout(filterGrpLt);
            GridData filterGrpGrDt = new GridData(GridData.FILL_BOTH);
            filterGrpGrDt.minimumWidth = 200;
            filterGrp.setLayoutData(filterGrpGrDt);
            filterGrp.setText(filterEnum.getLabel());

            final Table filterTable = new Table(filterGrp, SWT.CHECK | SWT.BORDER | SWT.V_SCROLL);
            GridData filterTableGrDt = new GridData(GridData.FILL_BOTH);
            filterTable.setLayoutData(filterTableGrDt);
            CheckboxTableViewer filterViewer = new CheckboxTableViewer(filterTable);
            filterViewer.setLabelProvider(new ColumnLabelProvider() {
                @Override
                public String getText(Object element) {
                    return element.toString();
                }
            });
            List<String> filterLabelList = new ArrayList<String>();
            List<String> filterValidLabelList = new ArrayList<String>();
            for (Filter filter : filterMap.get(filterEnum)) {
                filterLabelList.add(filter.getLabel());
                if (filter.isValid()) {
                    filterValidLabelList.add(filter.getLabel());
                } else {
                }
            }
            if (filterValidLabelList.isEmpty()) {
                filterValidLabelList.addAll(filterLabelList);
            }
            filterViewer.setContentProvider(new ArrayContentProvider());
            filterViewer.setInput(filterLabelList);
            filterViewer.setCheckedElements(filterValidLabelList.toArray());
            filterViewer.addCheckStateListener(new ICheckStateListener() {
                @Override
                public void checkStateChanged(CheckStateChangedEvent event) {
                    checkStateUpdate();
                }
            });

            filterTable.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseUp(MouseEvent e) {
                    if (e.button == 1) {
                        Point point = new Point(e.x, e.y);
                        TableItem item = filterTable.getItem(point);
                        if (item != null) {
                            Rectangle bounds = item.getBounds(0);
                            if (point.x > bounds.x + 5) {
                                boolean isChecked = filterViewer.getChecked(item.getData());
                                filterViewer.setChecked(item.getData(), !isChecked);
                                checkStateUpdate();
                            }
                        }
                    }
                }
            });

            final Button filterBulkBtn = new Button(filterGrp, SWT.CHECK);
            filterBulkBtn.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
            filterBulkBtn.setText("すべて");
            filterBulkBtn.setSelection(true);
            filterBulkBtn.addSelectionListener(new SelectionAdapter() {
                @Override
                public void widgetSelected(SelectionEvent e) {
                    if (filterBulkBtn.getSelection()) {
                        filterValidLabelList.addAll(filterLabelList);
                        filterViewer.setCheckedElements(filterValidLabelList.toArray());
                        filterViewer.refresh();
                    } else {
                        filterViewer.setCheckedElements(new ArrayList<String>().toArray());
                        filterViewer.refresh();
                    }
                    checkStateUpdate();
                }
            });

            treeViewerMap.put(filterEnum, filterViewer);
        }

        return composite;
    }

    private void checkStateUpdate() {
        for (FilterEnum filterEnum : FilterEnum.values()) {
            Object[] filterItems = treeViewerMap.get(filterEnum).getCheckedElements();
            List<String> strItems = new ArrayList<String>();
            for (Object item : filterItems) {
                strItems.add((String) item);
            }
            for (Filter filter : filterMap.get(filterEnum)) {
                if (strItems.contains(filter.getLabel())) {
                    filter.setValid(true);
                } else {
                    filter.setValid(false);
                }
            }
        }
        support.firePropertyChange("traceFilter", null, filterMap);
    }

    @Override
    protected void createButtonsForButtonBar(Composite parent) {
        createButton(parent, IDialogConstants.CANCEL_ID, "閉じる", true);
    }

    @Override
    protected void okPressed() {
        super.okPressed();
    }

    @Override
    protected void setShellStyle(int newShellStyle) {
        super.setShellStyle(SWT.CLOSE | SWT.TITLE | SWT.RESIZE | SWT.APPLICATION_MODAL);
    }

    @Override
    protected void configureShell(Shell newShell) {
        super.configureShell(newShell);
        newShell.setText("脆弱性フィルタ");
    }

    public void addPropertyChangeListener(PropertyChangeListener listener) {
        this.support.addPropertyChangeListener(listener);
    }

    public void removePropertyChangeListener(PropertyChangeListener listener) {
        this.support.removePropertyChangeListener(listener);
    }
}
