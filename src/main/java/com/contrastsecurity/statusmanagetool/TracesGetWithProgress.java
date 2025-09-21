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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.core.runtime.OperationCanceledException;
import org.eclipse.core.runtime.SubMonitor;
import org.eclipse.jface.dialogs.MessageDialog;
import org.eclipse.jface.operation.IRunnableWithProgress;
import org.eclipse.jface.preference.PreferenceStore;
import org.eclipse.swt.widgets.Shell;

import com.contrastsecurity.statusmanagetool.api.Api;
import com.contrastsecurity.statusmanagetool.api.ApiKeyApi;
import com.contrastsecurity.statusmanagetool.api.EventDetailApi;
import com.contrastsecurity.statusmanagetool.api.EventSummaryApi;
import com.contrastsecurity.statusmanagetool.api.GroupCreateApi;
import com.contrastsecurity.statusmanagetool.api.GroupsApi;
import com.contrastsecurity.statusmanagetool.api.HttpRequestApi;
import com.contrastsecurity.statusmanagetool.api.OrganizationsApi;
import com.contrastsecurity.statusmanagetool.api.StoryApi;
import com.contrastsecurity.statusmanagetool.api.SubStatusOTAliasApi;
import com.contrastsecurity.statusmanagetool.api.TraceApi;
import com.contrastsecurity.statusmanagetool.api.TracesApi;
import com.contrastsecurity.statusmanagetool.exception.ApiException;
import com.contrastsecurity.statusmanagetool.model.Chapter;
import com.contrastsecurity.statusmanagetool.model.CollapsedEventSummary;
import com.contrastsecurity.statusmanagetool.model.ContrastGroup;
import com.contrastsecurity.statusmanagetool.model.EventDetail;
import com.contrastsecurity.statusmanagetool.model.EventSummary;
import com.contrastsecurity.statusmanagetool.model.Filter;
import com.contrastsecurity.statusmanagetool.model.HttpRequest;
import com.contrastsecurity.statusmanagetool.model.ItemForVulnerability;
import com.contrastsecurity.statusmanagetool.model.Organization;
import com.contrastsecurity.statusmanagetool.model.Risk;
import com.contrastsecurity.statusmanagetool.model.Story;
import com.contrastsecurity.statusmanagetool.model.SubStatusOTAlias;
import com.contrastsecurity.statusmanagetool.model.Trace;
import com.contrastsecurity.statusmanagetool.preference.PreferenceConstants;

public class TracesGetWithProgress implements IRunnableWithProgress {

    private Shell shell;
    private PreferenceStore ps;
    private List<Organization> orgs;
    private VulnTypeEnum vulnType;
    private DetectTypeEnum detectType;
    private Date frDetectedDate;
    private Date toDetectedDate;
    private List<ItemForVulnerability> allVulns;
    private List<SubStatusOTAlias> aliasList;
    private Set<Filter> ruleNameFilterSet = new LinkedHashSet<Filter>();
    private Set<Filter> severityFilterSet = new LinkedHashSet<Filter>();
    private Set<Filter> applicationFilterSet = new LinkedHashSet<Filter>();
    private Set<Filter> organizationFilterSet = new LinkedHashSet<Filter>();
    private Set<Filter> statusFilterSet = new LinkedHashSet<Filter>();
    private Set<Filter> pendingStatusFilterSet = new LinkedHashSet<Filter>();

    Logger logger = LogManager.getLogger("csvdltool"); //$NON-NLS-1$

    public TracesGetWithProgress(Shell shell, PreferenceStore ps, List<Organization> orgs, VulnTypeEnum vulnType, DetectTypeEnum detectType, Date frDate, Date toDate) {
        this.shell = shell;
        this.ps = ps;
        this.orgs = orgs;
        this.vulnType = vulnType;
        this.detectType = detectType;
        this.frDetectedDate = frDate;
        this.toDetectedDate = toDate;
        this.allVulns = new ArrayList<ItemForVulnerability>();
        this.aliasList = new ArrayList<SubStatusOTAlias>();
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    @Override
    public void run(IProgressMonitor monitor) throws InvocationTargetException, InterruptedException {
        int sleepTrace = this.ps.getInt(PreferenceConstants.SLEEP_TRACE);
        SubMonitor subMonitor = SubMonitor.convert(monitor).setWorkRemaining(100);
        monitor.setTaskName("脆弱性一覧の読み込み...");
        boolean isSuperAdmin = this.ps.getBoolean(PreferenceConstants.IS_SUPERADMIN);
        Organization baseOrg = new Organization();
        baseOrg.setName("SuperAdmin");
        baseOrg.setOrganization_uuid(this.ps.getString(PreferenceConstants.ORG_ID));
        baseOrg.setApikey(this.ps.getString(PreferenceConstants.API_KEY));
        if (isSuperAdmin) {
            SubMonitor child1Monitor = subMonitor.split(20).setWorkRemaining(100);
            monitor.setTaskName("脆弱性一覧の読み込み...(SuperAdmin処理)");
            monitor.subTask("組織一覧の読み込み...");
            List<Organization> orgsForSuperAdmin = new ArrayList<Organization>();
            try {
                Api orgsApi = null;
                orgsApi = new OrganizationsApi(this.shell, this.ps, baseOrg, 0);
                List<Organization> tmpOrgs = (List<Organization>) orgsApi.get();
                int totalOrgCount = orgsApi.getTotalCount();
                orgsForSuperAdmin.addAll(tmpOrgs);
                boolean orgIncompleteFlg = false;
                orgIncompleteFlg = totalOrgCount > tmpOrgs.size();
                while (orgIncompleteFlg) {
                    Thread.sleep(100);
                    if (monitor.isCanceled()) {
                        throw new InterruptedException("キャンセルされました。");
                    }
                    orgsApi = new OrganizationsApi(this.shell, this.ps, baseOrg, orgsForSuperAdmin.size());
                    tmpOrgs = (List<Organization>) orgsApi.get();
                    orgsForSuperAdmin.addAll(tmpOrgs);
                    orgIncompleteFlg = totalOrgCount > orgsForSuperAdmin.size();
                }
            } catch (OperationCanceledException oce) {
                throw new InvocationTargetException(new OperationCanceledException("キャンセルされました。"));
            } catch (Exception e) {
                throw new InvocationTargetException(e);
            }
            this.orgs.clear();
            for (Organization org : orgsForSuperAdmin) {
                if (!org.isLocked()) {
                    this.orgs.add(org);
                }
            }
            child1Monitor.worked(30);
            Thread.sleep(500);
            if (this.ps.getBoolean(PreferenceConstants.IS_CREATEGROUP)) {
                monitor.subTask("権限グループの準備...");
                try {
                    List<ContrastGroup> groups = new ArrayList<ContrastGroup>();
                    Api groupsApi = new GroupsApi(this.shell, this.ps, baseOrg, 0);
                    List<ContrastGroup> tmpGroups = (List<ContrastGroup>) groupsApi.get();
                    int totalGroupCount = groupsApi.getTotalCount();
                    groups.addAll(tmpGroups);
                    boolean groupIncompleteFlg = false;
                    groupIncompleteFlg = totalGroupCount > tmpGroups.size();
                    while (groupIncompleteFlg) {
                        Thread.sleep(100);
                        if (monitor.isCanceled()) {
                            throw new InterruptedException("キャンセルされました。");
                        }
                        groupsApi = new GroupsApi(this.shell, this.ps, baseOrg, groups.size());
                        tmpGroups = (List<ContrastGroup>) groupsApi.get();
                        groups.addAll(tmpGroups);
                        groupIncompleteFlg = totalGroupCount > groups.size();
                    }
                    int groupId = -1;
                    for (ContrastGroup grp : groups) {
                        if (grp.getName().equals(this.ps.getString(PreferenceConstants.GROUP_NAME))) {
                            groupId = grp.getGroup_id();
                        }
                    }
                    if (groupId < 0) {
                        Api groupCreateApi = new GroupCreateApi(this.shell, this.ps, baseOrg, this.orgs);
                        String rtnMsg = (String) groupCreateApi.post();
                        if (rtnMsg.equals("true")) {
                            groups.clear();
                            groupsApi = new GroupsApi(this.shell, this.ps, baseOrg, 0);
                            tmpGroups = (List<ContrastGroup>) groupsApi.get();
                            totalGroupCount = groupsApi.getTotalCount();
                            groups.addAll(tmpGroups);
                            groupIncompleteFlg = false;
                            groupIncompleteFlg = totalGroupCount > tmpGroups.size();
                            while (groupIncompleteFlg) {
                                Thread.sleep(100);
                                if (monitor.isCanceled()) {
                                    throw new InterruptedException("キャンセルされました。");
                                }
                                groupsApi = new GroupsApi(this.shell, this.ps, baseOrg, groups.size());
                                tmpGroups = (List<ContrastGroup>) groupsApi.get();
                                groups.addAll(tmpGroups);
                                groupIncompleteFlg = totalGroupCount > groups.size();
                            }
                            groupId = -1;
                            for (ContrastGroup grp : groups) {
                                if (grp.getName().equals(this.ps.getString(PreferenceConstants.GROUP_NAME))) {
                                    groupId = grp.getGroup_id();
                                }
                            }
                            if (groupId < 0) {
                                throw new ApiException("一時グループの作成に失敗しました。");
                            }
                        }
                    }
                } catch (InterruptedException e) {
                    e.printStackTrace();
                } catch (ApiException e) {
                    e.printStackTrace();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            child1Monitor.worked(40);
            Thread.sleep(500);
            monitor.subTask("各組織のAPI Keyを取得...");
            for (Organization org : this.orgs) {
                if (org.isLocked()) {
                    org.setRemarks("ロックされています。");
                    continue;
                }
                try {
                    Api apiKeyApi = new ApiKeyApi(this.shell, this.ps, baseOrg, org.getOrganization_uuid());
                    org.setApikey((String) apiKeyApi.get());
                } catch (Exception e) {
                    e.printStackTrace();
                }
                Thread.sleep(100);
            }
            child1Monitor.worked(30);
            Thread.sleep(500);
        }

        SubMonitor child2Monitor = null;
        if (isSuperAdmin) {
            child2Monitor = subMonitor.split(80).setWorkRemaining(100 * this.orgs.size());
        } else {
            child2Monitor = subMonitor.split(100).setWorkRemaining(100 * this.orgs.size());
        }
        for (Organization org : this.orgs) {
            try {
                Api subStatusOTAliasApi = new SubStatusOTAliasApi(this.shell, this.ps, org);
                subStatusOTAliasApi.setIgnoreStatusCodes(new ArrayList(Arrays.asList(404)));
                SubStatusOTAlias alias = (SubStatusOTAlias) subStatusOTAliasApi.get();
                if (alias != null) {
                    this.aliasList.add(alias);
                }
                monitor.setTaskName(String.format("%s 脆弱性一覧の読み込み...", org.getName()));
                monitor.subTask("脆弱性一覧を読み込んでいます...");
                List<ItemForVulnerability> allTraces = new ArrayList<ItemForVulnerability>();
                Api tracesApi = new TracesApi(this.shell, this.ps, org, this.vulnType, this.detectType, frDetectedDate, toDetectedDate, 0);
                List<ItemForVulnerability> tmpTraces = (List<ItemForVulnerability>) tracesApi.post();
                int totalTracesCount = tracesApi.getTotalCount();
                int traceProcessCount = 0;
                monitor.setTaskName(String.format("%s 脆弱性一覧の読み込み...(%d/%d)", org.getName(), traceProcessCount, totalTracesCount)); //$NON-NLS-1$
                SubMonitor child2_1Monitor = child2Monitor.split(100).setWorkRemaining(totalTracesCount);
                for (ItemForVulnerability vul : tmpTraces) {
                    if (monitor.isCanceled()) {
                        throw new OperationCanceledException();
                    }
                    Thread.sleep(50);
                    Api traceApi = new TraceApi(this.shell, this.ps, org, vul.getVulnerability().getApplication().getId(), vul.getVulnerability().getUuid());
                    Trace trace = (Trace) traceApi.get();
                    vul.getVulnerability().setNotes(trace.getNotes());
                    vul.getVulnerability().setOrg(org);
                    child2_1Monitor.worked(1);
                    traceProcessCount++;
                    monitor.setTaskName(String.format("%s 脆弱性一覧の読み込み...(%d/%d)", org.getName(), traceProcessCount, totalTracesCount)); //$NON-NLS-1$
                    monitor.subTask(trace.getTitle());

                    Api storyApi = new StoryApi(this.shell, this.ps, org, vul.getVulnerability().getUuid());
                    Story story = null;
                    try {
                        story = (Story) storyApi.get();
                    } catch (Exception e) {
                        this.shell.getDisplay().syncExec(new Runnable() {
                            public void run() {
                                if (!MessageDialog.openConfirm(shell, Messages.getString("vulgetwithprogress.message.dialog.title"), //$NON-NLS-1$
                                        Messages.getString("vulgetwithprogress.message.dialog.overview.get.error.message"))) { //$NON-NLS-1$
                                    monitor.setCanceled(true);
                                }
                            }
                        });
                        Risk risk = new Risk();
                        risk.setText(Messages.getString("vulgetwithprogress.detail.header.get.error")); //$NON-NLS-1$
                        story = new Story();
                        story.setRisk(risk);
                        story.setChapters(new ArrayList<Chapter>());
                    }
                    vul.getVulnerability().setStory(story);

                    Api httpRequestApi = new HttpRequestApi(this.shell, this.ps, org, vul.getVulnerability().getUuid());
                    HttpRequest httpRequest = (HttpRequest) httpRequestApi.get();
                    vul.getVulnerability().setHttpRequest(httpRequest);

                    Api eventSummaryApi = new EventSummaryApi(this.shell, this.ps, org, vul.getVulnerability().getUuid());
                    List<EventSummary> eventSummaries = (List<EventSummary>) eventSummaryApi.get();
                    vul.getVulnerability().setEventSummaries(eventSummaries);
                    for (EventSummary es : eventSummaries) {
                        if (es.getCollapsedEvents() != null && es.getCollapsedEvents().isEmpty()) {
                            Api eventDetailApi = new EventDetailApi(this.shell, this.ps, org, vul.getVulnerability().getUuid(), es.getId());
                            EventDetail ed = (EventDetail) eventDetailApi.get();
                            vul.getVulnerability().addEventDetail(ed);
                        } else {
                            for (CollapsedEventSummary ce : es.getCollapsedEvents()) {
                                Api eventDetailApi = new EventDetailApi(this.shell, this.ps, org, vul.getVulnerability().getUuid(), ce.getId());
                                EventDetail ed = (EventDetail) eventDetailApi.get();
                                vul.getVulnerability().addEventDetail(ed);
                            }
                        }
                    }
                    if (sleepTrace > 0) {
                        Thread.sleep(sleepTrace);
                    }
                }
                allTraces.addAll(tmpTraces);
                boolean traceIncompleteFlg = false;
                traceIncompleteFlg = totalTracesCount > allTraces.size();
                while (traceIncompleteFlg) {
                    Thread.sleep(100);
                    tracesApi = new TracesApi(this.shell, this.ps, org, this.vulnType, this.detectType, frDetectedDate, toDetectedDate, allTraces.size());
                    tmpTraces = (List<ItemForVulnerability>) tracesApi.post();
                    for (ItemForVulnerability vul : tmpTraces) {
                        if (monitor.isCanceled()) {
                            throw new OperationCanceledException();
                        }
                        Thread.sleep(50);
                        Api traceApi = new TraceApi(this.shell, this.ps, org, vul.getVulnerability().getApplication().getId(), vul.getVulnerability().getUuid());
                        Trace trace = (Trace) traceApi.get();
                        vul.getVulnerability().setNotes(trace.getNotes());
                        vul.getVulnerability().setOrg(org);
                        child2_1Monitor.worked(1);
                        traceProcessCount++;
                        monitor.setTaskName(String.format("%s 脆弱性一覧の読み込み...(%d/%d)", org.getName(), traceProcessCount, totalTracesCount)); //$NON-NLS-1$
                        monitor.subTask(trace.getTitle());
                        Api storyApi = new StoryApi(this.shell, this.ps, org, vul.getVulnerability().getUuid());
                        Story story = null;
                        try {
                            story = (Story) storyApi.get();
                        } catch (Exception e) {
                            this.shell.getDisplay().syncExec(new Runnable() {
                                public void run() {
                                    if (!MessageDialog.openConfirm(shell, Messages.getString("vulgetwithprogress.message.dialog.title"), //$NON-NLS-1$
                                            Messages.getString("vulgetwithprogress.message.dialog.overview.get.error.message"))) { //$NON-NLS-1$
                                        monitor.setCanceled(true);
                                    }
                                }
                            });
                            Risk risk = new Risk();
                            risk.setText(Messages.getString("vulgetwithprogress.detail.header.get.error")); //$NON-NLS-1$
                            story = new Story();
                            story.setRisk(risk);
                            story.setChapters(new ArrayList<Chapter>());
                        }
                        vul.getVulnerability().setStory(story);

                        Api httpRequestApi = new HttpRequestApi(this.shell, this.ps, org, vul.getVulnerability().getUuid());
                        HttpRequest httpRequest = (HttpRequest) httpRequestApi.get();
                        vul.getVulnerability().setHttpRequest(httpRequest);

                        Api eventSummaryApi = new EventSummaryApi(this.shell, this.ps, org, vul.getVulnerability().getUuid());
                        List<EventSummary> eventSummaries = (List<EventSummary>) eventSummaryApi.get();
                        vul.getVulnerability().setEventSummaries(eventSummaries);
                        for (EventSummary es : eventSummaries) {
                            if (es.getCollapsedEvents() != null && es.getCollapsedEvents().isEmpty()) {
                                Api eventDetailApi = new EventDetailApi(this.shell, this.ps, org, vul.getVulnerability().getUuid(), es.getId());
                                EventDetail ed = (EventDetail) eventDetailApi.get();
                                vul.getVulnerability().addEventDetail(ed);
                            } else {
                                for (CollapsedEventSummary ce : es.getCollapsedEvents()) {
                                    Api eventDetailApi = new EventDetailApi(this.shell, this.ps, org, vul.getVulnerability().getUuid(), ce.getId());
                                    EventDetail ed = (EventDetail) eventDetailApi.get();
                                    vul.getVulnerability().addEventDetail(ed);
                                }
                            }
                        }
                        if (sleepTrace > 0) {
                            Thread.sleep(sleepTrace);
                        }
                    }
                    allTraces.addAll(tmpTraces);
                    traceIncompleteFlg = totalTracesCount > allTraces.size();
                }
                this.allVulns.addAll(allTraces);
                child2_1Monitor.done();
                Thread.sleep(100);
            } catch (OperationCanceledException oce) {
                throw new InvocationTargetException(new OperationCanceledException("キャンセルされました。"));
            } catch (Exception e) {
                throw new InvocationTargetException(e);
            }
            Thread.sleep(1000);
        }
        subMonitor.done();
    }

    public List<ItemForVulnerability> getAllVulns() {
        return this.allVulns;
    }

    public Map<FilterEnum, Set<Filter>> getFilterMap() {
        for (ItemForVulnerability vuln : this.allVulns) {
            ruleNameFilterSet.add(new Filter(vuln.getVulnerability().getRuleName()));
            severityFilterSet.add(new Filter(SeverityEnum.valueOf(vuln.getVulnerability().getSeverity()).getLabel(), vuln.getVulnerability().getSeverity()));
            applicationFilterSet.add(new Filter(vuln.getVulnerability().getApplication().getName()));
            organizationFilterSet.add(new Filter(vuln.getVulnerability().getOrg().getName()));
            Optional<StatusEnum> status = StatusEnum.fromValue(vuln.getVulnerability().getStatus());
            status.ifPresentOrElse(s -> statusFilterSet.add(new Filter(s.getLabel(), vuln.getVulnerability().getStatus())),
                    () -> statusFilterSet.add(new Filter(vuln.getVulnerability().getStatus())));
            if (vuln.getVulnerability().getPendingStatus() != null) {
                Optional<StatusEnum> pendingStatus = StatusEnum.fromValue(vuln.getVulnerability().getPendingStatus().getStatus());
                pendingStatus.ifPresentOrElse(s -> pendingStatusFilterSet.add(new Filter(s.getLabel(), vuln.getVulnerability().getStatus())),
                        () -> pendingStatusFilterSet.add(new Filter(vuln.getVulnerability().getStatus())));
            }
        }
        Map<FilterEnum, Set<Filter>> filterMap = new HashMap<FilterEnum, Set<Filter>>();
        filterMap.put(FilterEnum.RULE_NAME, ruleNameFilterSet);
        filterMap.put(FilterEnum.SEVERITY, severityFilterSet);
        filterMap.put(FilterEnum.APP_NAME, applicationFilterSet);
        filterMap.put(FilterEnum.ORG_NAME, organizationFilterSet);
        filterMap.put(FilterEnum.STATUS, statusFilterSet);
        filterMap.put(FilterEnum.PENDING_STATUS, pendingStatusFilterSet);
        return filterMap;
    }

    public List<Organization> getOrgs() {
        return this.orgs;
    }

    public List<SubStatusOTAlias> getAliasList() {
        return aliasList;
    }

}
