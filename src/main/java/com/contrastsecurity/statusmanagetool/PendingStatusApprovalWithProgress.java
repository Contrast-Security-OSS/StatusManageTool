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

import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.core.runtime.OperationCanceledException;
import org.eclipse.core.runtime.SubMonitor;
import org.eclipse.jface.operation.IRunnableWithProgress;
import org.eclipse.jface.preference.PreferenceStore;
import org.eclipse.swt.widgets.Shell;

import com.contrastsecurity.statusmanagetool.api.Api;
import com.contrastsecurity.statusmanagetool.api.ApprovalWorkflowApi;
import com.contrastsecurity.statusmanagetool.json.PendingStatusApprovalJson;
import com.contrastsecurity.statusmanagetool.model.ItemForVulnerability;
import com.contrastsecurity.statusmanagetool.model.Organization;

public class PendingStatusApprovalWithProgress implements IRunnableWithProgress {

    private Shell shell;
    private PreferenceStore ps;
    private Map<Organization, List<ItemForVulnerability>> targetMap;
    private boolean approved;
    private String note;
    private List<PendingStatusApprovalJson> jsonList;

    Logger logger = LogManager.getLogger("csvdltool"); //$NON-NLS-1$

    public PendingStatusApprovalWithProgress(Shell shell, PreferenceStore ps, Map<Organization, List<ItemForVulnerability>> targetMap, boolean approved) {
        this.shell = shell;
        this.ps = ps;
        this.targetMap = targetMap;
        this.approved = approved;
    }

    public PendingStatusApprovalWithProgress(Shell shell, PreferenceStore ps, Map<Organization, List<ItemForVulnerability>> targetMap, boolean approved, String note) {
        this.shell = shell;
        this.ps = ps;
        this.targetMap = targetMap;
        this.approved = approved;
        this.note = note;
    }

    @Override
    public void run(IProgressMonitor monitor) throws InvocationTargetException, InterruptedException {
        SubMonitor subMonitor = SubMonitor.convert(monitor).setWorkRemaining(this.targetMap.size());
        monitor.setTaskName(this.approved ? "保留中の脆弱性ステータスを承認しています..." : "保留中の脆弱性ステータスを拒否しています...");
        for (Map.Entry<Organization, List<ItemForVulnerability>> entry : this.targetMap.entrySet()) {
            Organization org = entry.getKey();
            List<ItemForVulnerability> vulns = entry.getValue();
            if (vulns.isEmpty()) {
                continue;
            }
            try {
                monitor.setTaskName(String.format("%s", org.getName()));
                monitor.subTask(String.format("%d件更新しています。", vulns.size()));
                Api pendingStatusApprovalApi = new ApprovalWorkflowApi(this.shell, this.ps, org, vulns, this.approved, this.note);
                PendingStatusApprovalJson resJson = (PendingStatusApprovalJson) pendingStatusApprovalApi.post();
                this.jsonList.add(resJson);
                subMonitor.worked(1);
                Thread.sleep(500);
            } catch (OperationCanceledException oce) {
                throw new InvocationTargetException(new OperationCanceledException("キャンセルされました。"));
            } catch (Exception e) {
                throw new InvocationTargetException(e);
            }
        }
        subMonitor.done();
    }

    public List<PendingStatusApprovalJson> getJsonList() {
        return jsonList;
    }

}
