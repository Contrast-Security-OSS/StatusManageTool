package com.contrastsecurity.statusmanagetool;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import java.text.SimpleDateFormat;
import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.temporal.TemporalAdjusters;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.IntStream;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jface.dialogs.IDialogConstants;
import org.eclipse.jface.dialogs.MessageDialog;
import org.eclipse.jface.dialogs.ProgressMonitorDialog;
import org.eclipse.jface.preference.PreferenceStore;
import org.eclipse.swt.SWT;
import org.eclipse.swt.custom.CTabFolder;
import org.eclipse.swt.custom.CTabItem;
import org.eclipse.swt.custom.SashForm;
import org.eclipse.swt.custom.TableEditor;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.graphics.Color;
import org.eclipse.swt.graphics.Font;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Event;
import org.eclipse.swt.widgets.Group;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Listener;
import org.eclipse.swt.widgets.Menu;
import org.eclipse.swt.widgets.MessageBox;
import org.eclipse.swt.widgets.Table;
import org.eclipse.swt.widgets.TableColumn;
import org.eclipse.swt.widgets.TableItem;
import org.eclipse.swt.widgets.Text;

import com.contrastsecurity.statusmanagetool.exception.ApiException;
import com.contrastsecurity.statusmanagetool.exception.NonApiException;
import com.contrastsecurity.statusmanagetool.json.ContrastJson;
import com.contrastsecurity.statusmanagetool.json.PendingStatusApprovalJson;
import com.contrastsecurity.statusmanagetool.model.Filter;
import com.contrastsecurity.statusmanagetool.model.ItemForVulnerability;
import com.contrastsecurity.statusmanagetool.model.Organization;
import com.contrastsecurity.statusmanagetool.preference.OtherPreferencePage;
import com.contrastsecurity.statusmanagetool.preference.PreferenceConstants;

public class VulTabItem extends CTabItem implements PropertyChangeListener {

    private Button traceLoadBtn;

    private final SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd(E)");

    private Map<FilterEnum, Set<Filter>> traceFilterMap;

    private boolean isBulkOn;
    private boolean isFirstDetectSortDesc;
    private boolean isLastDetectSortDesc;
    private boolean isSeveritySortDesc;

    private Label traceCount;
    private Button vulnTypeAllBtn;
    private Button vulnTypeOpenBtn;
    private Button vulnTypeHighConfidenceBtn;
    private Button vulnTypePendingBtn;
    private Map<VulnTypeEnum, Button> vulnTypeBtnMap;
    private Map<DetectTypeEnum, Button> detectTypeBtnMap;
    private Button firstDetectBtn;
    private Button lastDetectBtn;
    private List<Button> traceDetectedRadios = new ArrayList<Button>();
    private Button traceTermHalf1st;
    private Button traceTermHalf2nd;
    private Button traceTerm30days;
    private Button traceTermYesterday;
    private Button traceTermToday;
    private Button traceTermLastWeek;
    private Button traceTermThisWeek;
    private Button traceTermPeriod;
    private Text traceDetectedFilterTxt;
    private Date frDetectedDate;
    private Date toDetectedDate;
    private Table traceTable;
    private List<Button> checkBoxList = new ArrayList<Button>();
    private List<Integer> selectedIdxes = new ArrayList<Integer>();
    private List<ItemForVulnerability> traces;
    private List<ItemForVulnerability> filteredTraces = new ArrayList<ItemForVulnerability>();
    private Map<TraceDetectedDateFilterEnum, Date> traceDetectedFilterMap;
    private Button statusChangeBtn;
    private Button approveBtn;
    private Button rejectBtn;

    private CTabFolder subTabFolder;

    private PreferenceStore ps;

    private PropertyChangeSupport support = new PropertyChangeSupport(this);

    Logger logger = LogManager.getLogger("vulnstatusmanagetool");

    public VulTabItem(CTabFolder mainTabFolder, VulnStatusManageToolShell toolShell, PreferenceStore ps) {
        super(mainTabFolder, SWT.NONE);
        this.ps = ps;
        setText("脆弱性");

        this.traceDetectedFilterMap = getTraceDetectedDateMap();

        Composite shell = new Composite(mainTabFolder, SWT.NONE);
        shell.setLayout(new GridLayout(1, false));

        Group vulnListGrp = new Group(shell, SWT.NONE);
        vulnListGrp.setLayout(new GridLayout(3, false));
        GridData vulnListGrpGrDt = new GridData(GridData.FILL_BOTH);
        vulnListGrpGrDt.minimumHeight = 200;
        vulnListGrp.setLayoutData(vulnListGrpGrDt);

        Composite vulnTypeGrp = new Composite(vulnListGrp, SWT.NONE);
        vulnTypeGrp.setLayout(new GridLayout(4, false));
        GridData vulnTypeGrpGrDt = new GridData(GridData.FILL_HORIZONTAL);
        vulnTypeGrp.setLayoutData(vulnTypeGrpGrDt);

        vulnTypeBtnMap = new HashMap<VulnTypeEnum, Button>();
        vulnTypeAllBtn = new Button(vulnTypeGrp, SWT.RADIO);
        vulnTypeOpenBtn = new Button(vulnTypeGrp, SWT.RADIO);
        vulnTypeHighConfidenceBtn = new Button(vulnTypeGrp, SWT.RADIO);
        vulnTypePendingBtn = new Button(vulnTypeGrp, SWT.RADIO);
        vulnTypeBtnMap.put(VulnTypeEnum.ALL, vulnTypeAllBtn);
        vulnTypeBtnMap.put(VulnTypeEnum.OPEN, vulnTypeOpenBtn);
        vulnTypeBtnMap.put(VulnTypeEnum.HIGH_CONFIDENCE, vulnTypeHighConfidenceBtn);
        vulnTypeBtnMap.put(VulnTypeEnum.PENDING_REVIEW, vulnTypePendingBtn);
        vulnTypeBtnMap.forEach((key, value) -> {
            value.setText(key.getLabel());
            value.setSelection(false);
        });

        Group detectGrp = new Group(vulnListGrp, SWT.NONE);
        detectGrp.setLayout(new GridLayout(1, false));
        GridData detectGrpGrDt = new GridData(GridData.FILL_HORIZONTAL);
        detectGrpGrDt.horizontalSpan = 3;
        detectGrp.setLayoutData(detectGrpGrDt);
        detectGrp.setText("検出日時");
        VulnTypeEnum vulnTypeEnum = VulnTypeEnum.valueOf(this.ps.getString(PreferenceConstants.VULN_CHOICE));
        Button selectedVulnTypeBtn = vulnTypeBtnMap.get(vulnTypeEnum);
        if (selectedVulnTypeBtn != null) {
            selectedVulnTypeBtn.setSelection(true);
        } else {
            vulnTypeAllBtn.setSelection(true);
        }

        Composite detectTypeGrp = new Composite(detectGrp, SWT.NONE);
        detectTypeGrp.setLayout(new GridLayout(10, false));
        GridData detectTypeGrpGrDt = new GridData(GridData.FILL_HORIZONTAL);
        detectTypeGrp.setLayoutData(detectTypeGrpGrDt);

        detectTypeBtnMap = new HashMap<DetectTypeEnum, Button>();
        firstDetectBtn = new Button(detectTypeGrp, SWT.RADIO);
        lastDetectBtn = new Button(detectTypeGrp, SWT.RADIO);
        detectTypeBtnMap.put(DetectTypeEnum.FIRST, firstDetectBtn);
        detectTypeBtnMap.put(DetectTypeEnum.LAST, lastDetectBtn);
        detectTypeBtnMap.forEach((key, value) -> {
            value.setText(key.getLabel());
            value.setSelection(false);
        });
        DetectTypeEnum detectTypeEnum = DetectTypeEnum.valueOf(this.ps.getString(PreferenceConstants.DETECT_CHOICE));
        Button selectedDetectTypeBtn = detectTypeBtnMap.get(detectTypeEnum);
        if (selectedDetectTypeBtn != null) {
            selectedDetectTypeBtn.setSelection(true);
        } else {
            firstDetectBtn.setSelection(true);
        }

        if (this.ps.getString(PreferenceConstants.DETECT_CHOICE).equals("FIRST")) {
            firstDetectBtn.setSelection(true);
        } else {
            lastDetectBtn.setSelection(true);
        }

        Composite detectTermGrp = new Composite(detectGrp, SWT.NONE);
        detectTermGrp.setLayout(new GridLayout(10, false));
        GridData detectTermGrpGrDt = new GridData(GridData.FILL_HORIZONTAL);
        detectTermGrp.setLayoutData(detectTermGrpGrDt);

        new Label(detectTermGrp, SWT.LEFT).setText("取得期間：");
        // =============== 取得期間選択ラジオボタン ===============
        // 上半期
        traceTermHalf1st = new Button(detectTermGrp, SWT.RADIO);
        traceTermHalf1st.setText("上半期");
        traceDetectedRadios.add(traceTermHalf1st);
        traceTermHalf1st.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                frDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.HALF_1ST_START);
                toDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.HALF_1ST_END);
                detectedDateLabelUpdate();
            }

        });
        // 下半期
        traceTermHalf2nd = new Button(detectTermGrp, SWT.RADIO);
        traceTermHalf2nd.setText("下半期");
        traceDetectedRadios.add(traceTermHalf2nd);
        traceTermHalf2nd.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                frDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.HALF_2ND_START);
                toDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.HALF_2ND_END);
                detectedDateLabelUpdate();
            }

        });
        // 直近30日間
        traceTerm30days = new Button(detectTermGrp, SWT.RADIO);
        traceTerm30days.setText("直近30日間");
        traceDetectedRadios.add(traceTerm30days);
        traceTerm30days.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                frDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.BEFORE_30_DAYS);
                toDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.TODAY);
                detectedDateLabelUpdate();
            }
        });
        // 昨日
        traceTermYesterday = new Button(detectTermGrp, SWT.RADIO);
        traceTermYesterday.setText("昨日");
        traceDetectedRadios.add(traceTermYesterday);
        traceTermYesterday.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                frDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.YESTERDAY);
                toDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.YESTERDAY);
                detectedDateLabelUpdate();
            }
        });
        // 今日
        traceTermToday = new Button(detectTermGrp, SWT.RADIO);
        traceTermToday.setText("今日");
        traceDetectedRadios.add(traceTermToday);
        traceTermToday.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                frDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.TODAY);
                toDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.TODAY);
                detectedDateLabelUpdate();
            }
        });
        // 先週
        traceTermLastWeek = new Button(detectTermGrp, SWT.RADIO);
        traceTermLastWeek.setText("先週");
        traceDetectedRadios.add(traceTermLastWeek);
        traceTermLastWeek.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                frDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.LAST_WEEK_START);
                toDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.LAST_WEEK_END);
                detectedDateLabelUpdate();
            }
        });
        // 今週
        traceTermThisWeek = new Button(detectTermGrp, SWT.RADIO);
        traceTermThisWeek.setText("今週");
        traceDetectedRadios.add(traceTermThisWeek);
        traceTermThisWeek.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                frDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.THIS_WEEK_START);
                toDetectedDate = traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.THIS_WEEK_END);
                detectedDateLabelUpdate();
            }
        });
        // 任意の期間
        traceTermPeriod = new Button(detectTermGrp, SWT.RADIO);
        traceTermPeriod.setText("任意");
        traceDetectedRadios.add(traceTermPeriod);
        traceTermPeriod.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                String datePeriodStr = ps.getString(PreferenceConstants.DETECT_PERIOD);
                if (datePeriodStr.matches("^\\d{13}-\\d{13}$")) {
                    String[] periodArray = datePeriodStr.split("-");
                    if (periodArray.length > 1) {
                        long frms = Long.parseLong(periodArray[0]);
                        long toms = Long.parseLong(periodArray[1]);
                        frDetectedDate = new Date(frms);
                        toDetectedDate = new Date(toms);
                    }
                }
                detectedDateLabelUpdate();
            }
        });
        traceDetectedFilterTxt = new Text(detectTermGrp, SWT.BORDER);
        traceDetectedFilterTxt.setText("");
        traceDetectedFilterTxt.setEditable(false);
        traceDetectedFilterTxt.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
        traceDetectedFilterTxt.addListener(SWT.MouseUp, new Listener() {
            public void handleEvent(Event e) {
                if (!traceTermPeriod.getSelection()) {
                    return;
                }
                FilterDetectedDateDialog filterDialog = new FilterDetectedDateDialog(toolShell, frDetectedDate, toDetectedDate);
                int result = filterDialog.open();
                if (IDialogConstants.OK_ID != result) {
                    traceLoadBtn.setFocus();
                    return;
                }
                frDetectedDate = filterDialog.getFrDate();
                toDetectedDate = filterDialog.getToDate();
                if (frDetectedDate.getTime() > toDetectedDate.getTime()) {
                    MessageDialog.openError(toolShell, "任意の期間", "取得期間のFrom, Toの指定が不正です。");
                    return;
                }
                ps.setValue(PreferenceConstants.DETECT_PERIOD, String.format("%s-%s", frDetectedDate.getTime(), toDetectedDate.getTime()));
                detectedDateLabelUpdate();
                if (!traceDetectedFilterTxt.getText().isEmpty()) {
                    for (Button rdo : traceDetectedRadios) {
                        rdo.setSelection(false);
                    }
                    traceTermPeriod.setSelection(true);
                }
                traceLoadBtn.setFocus();
            }
        });
        for (Button termBtn : this.traceDetectedRadios) {
            updateTermFilterOption();
            termBtn.setSelection(false);
            if (this.traceDetectedRadios.indexOf(termBtn) == this.ps.getInt(PreferenceConstants.TRACE_DETECTED_DATE_FILTER)) {
                termBtn.setSelection(true);
                Event event = new Event();
                event.widget = termBtn;
                event.type = SWT.Selection;
                termBtn.notifyListeners(SWT.Selection, event);
            }
        }
        if (traceTermPeriod.getSelection()) {
            String datePeriodStr = this.ps.getString(PreferenceConstants.DETECT_PERIOD);
            if (datePeriodStr.matches("^\\d{13}-\\d{13}$")) {
                String[] periodArray = datePeriodStr.split("-");
                if (periodArray.length > 1) {
                    long frms = Long.parseLong(periodArray[0]);
                    long toms = Long.parseLong(periodArray[1]);
                    frDetectedDate = new Date(frms);
                    toDetectedDate = new Date(toms);
                }
            }
        }
        detectedDateLabelUpdate();

        traceLoadBtn = new Button(vulnListGrp, SWT.PUSH);
        GridData traceLoadBtnGrDt = new GridData(GridData.FILL_HORIZONTAL);
        traceLoadBtnGrDt.horizontalSpan = 3;
        traceLoadBtnGrDt.heightHint = 30;
        traceLoadBtn.setLayoutData(traceLoadBtnGrDt);
        traceLoadBtn.setText("脆弱性一覧を取得");
        traceLoadBtn.setToolTipText("脆弱性一覧を取得します。");
        traceLoadBtn.setFont(new Font(toolShell.getDisplay(), "ＭＳ ゴシック", 14, SWT.BOLD));
        traceLoadBtn.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent event) {
                uiReset();
                Date[] frToDate = getFrToDetectedDate();
                if (frToDate.length != 2) {
                    MessageDialog.openError(toolShell, "脆弱性一覧の取得", "取得期間を設定してください。");
                    return;
                }
                TracesGetWithProgress progress = new TracesGetWithProgress(toolShell, ps, toolShell.getMain().getValidOrganizations(), getSelectedVulnType(),
                        getSelectedDetectType(), frToDate[0], frToDate[1]);
                ProgressMonitorDialog progDialog = new TracesGetProgressMonitorDialog(toolShell);
                try {
                    progDialog.run(true, true, progress);
                    traces = progress.getAllVulns();
                    Collections.sort(traces, new Comparator<ItemForVulnerability>() {
                        @Override
                        public int compare(ItemForVulnerability e1, ItemForVulnerability e2) {
                            return e1.getVulnerability().getFirstDetected().compareTo(e2.getVulnerability().getFirstDetected());
                        }
                    });
                    filteredTraces.addAll(traces);
                    for (ItemForVulnerability vuln : traces) {
                        addColToVulnTable(vuln, -1);
                    }
                    traceFilterMap = progress.getFilterMap();
                    traceCount.setText(String.format("%d/%d", filteredTraces.size(), traces.size()));
                    if (ps.getBoolean(PreferenceConstants.IS_SUPERADMIN)) {
                        toolShell.getMain().setOrgsForSuperAdminOpe(progress.getOrgs());
                    }
                } catch (InvocationTargetException e) {
                    StringWriter stringWriter = new StringWriter();
                    PrintWriter printWriter = new PrintWriter(stringWriter);
                    e.printStackTrace(printWriter);
                    String trace = stringWriter.toString();
                    logger.error(trace);
                    String errorMsg = e.getTargetException().getMessage();
                    if (e.getTargetException() instanceof ApiException) {
                        MessageDialog.openWarning(toolShell, "脆弱性一覧の取得", String.format("TeamServerからエラーが返されました。\r\n%s", errorMsg));
                    } else if (e.getTargetException() instanceof NonApiException) {
                        MessageDialog.openError(toolShell, "脆弱性一覧の取得", String.format("想定外のステータスコード: %s\r\nログファイルをご確認ください。", errorMsg));
                    } else {
                        MessageDialog.openError(toolShell, "脆弱性一覧の取得", String.format("不明なエラーです。ログファイルをご確認ください。\r\n%s", errorMsg));
                    }
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });

        SashForm sashForm = new SashForm(vulnListGrp, SWT.VERTICAL);
        GridData sashFormGrDt = new GridData(GridData.FILL_BOTH);
        sashFormGrDt.horizontalSpan = 3;
        sashForm.setLayoutData(sashFormGrDt);

        Composite topComposite = new Composite(sashForm, SWT.NONE);
        topComposite.setLayout(new GridLayout(3, false));
        GridData topCompositeGrDt = new GridData(GridData.FILL_HORIZONTAL);
        topComposite.setLayoutData(topCompositeGrDt);

        this.traceCount = new Label(topComposite, SWT.RIGHT);
        GridData traceCountGrDt = new GridData(GridData.FILL_HORIZONTAL);
        traceCountGrDt.horizontalSpan = 3;
        traceCountGrDt.minimumHeight = 12;
        traceCountGrDt.minimumWidth = 30;
        traceCountGrDt.heightHint = 12;
        traceCountGrDt.widthHint = 30;
        this.traceCount.setLayoutData(traceCountGrDt);
        this.traceCount.setFont(new Font(toolShell.getDisplay(), "ＭＳ ゴシック", 10, SWT.NORMAL));
        this.traceCount.setText("0/0");

        traceTable = new Table(topComposite, SWT.BORDER | SWT.FULL_SELECTION | SWT.MULTI);
        GridData traceTableGrDt = new GridData(GridData.FILL_BOTH);
        traceTableGrDt.horizontalSpan = 3;
        traceTable.setLayoutData(traceTableGrDt);
        traceTable.setLinesVisible(true);
        traceTable.setHeaderVisible(true);
        Menu menuTable = new Menu(traceTable);
        traceTable.setMenu(menuTable);
        traceTable.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                ItemForVulnerability selectedVul = filteredTraces.get(traceTable.getSelectionIndex());
                support.firePropertyChange("selectedTraceChanged", null, selectedVul);
            }
        });

        TableColumn column0 = new TableColumn(traceTable, SWT.NONE);
        column0.setWidth(0);
        column0.setResizable(false);
        TableColumn column1 = new TableColumn(traceTable, SWT.CENTER);
        column1.setWidth(50);
        column1.setText("有効");
        column1.addListener(SWT.Selection, new Listener() {
            @Override
            public void handleEvent(Event event) {
                isBulkOn = !isBulkOn;
                if (selectedIdxes.isEmpty()) {
                    isBulkOn = true;
                } else {
                    if (filteredTraces.size() == selectedIdxes.size()) {
                        isBulkOn = false;
                    }
                }
                if (isBulkOn) {
                    selectedIdxes.clear();
                    for (Button button : checkBoxList) {
                        button.setSelection(true);
                        selectedIdxes.add(checkBoxList.indexOf(button));
                    }
                } else {
                    selectedIdxes.clear();
                    for (Button button : checkBoxList) {
                        button.setSelection(false);
                    }
                }
                updateBtnStatus();
            }
        });
        TableColumn column2 = new TableColumn(traceTable, SWT.CENTER);
        column2.setWidth(150);
        column2.setText("最初の検知日時");
        column2.addListener(SWT.Selection, new Listener() {
            @Override
            public void handleEvent(Event event) {
                isFirstDetectSortDesc = !isFirstDetectSortDesc;
                traceTable.clearAll();
                traceTable.removeAll();
                if (isFirstDetectSortDesc) {
                    Collections.reverse(traces);
                    Collections.reverse(filteredTraces);
                } else {
                    Collections.sort(traces, new Comparator<ItemForVulnerability>() {
                        @Override
                        public int compare(ItemForVulnerability e1, ItemForVulnerability e2) {
                            return e1.getVulnerability().getFirstDetected().compareTo(e2.getVulnerability().getFirstDetected());
                        }
                    });
                    Collections.sort(filteredTraces, new Comparator<ItemForVulnerability>() {
                        @Override
                        public int compare(ItemForVulnerability e1, ItemForVulnerability e2) {
                            return e1.getVulnerability().getFirstDetected().compareTo(e2.getVulnerability().getFirstDetected());
                        }
                    });
                }
                for (ItemForVulnerability vul : filteredTraces) {
                    addColToVulnTable(vul, -1);
                }
            }
        });
        TableColumn column3 = new TableColumn(traceTable, SWT.CENTER);
        column3.setWidth(150);
        column3.setText("最後の検知日時");
        column3.addListener(SWT.Selection, new Listener() {
            @Override
            public void handleEvent(Event event) {
                isLastDetectSortDesc = !isLastDetectSortDesc;
                traceTable.clearAll();
                traceTable.removeAll();
                if (isLastDetectSortDesc) {
                    Collections.reverse(traces);
                    Collections.reverse(filteredTraces);
                } else {
                    Collections.sort(traces, new Comparator<ItemForVulnerability>() {
                        @Override
                        public int compare(ItemForVulnerability e1, ItemForVulnerability e2) {
                            return e1.getVulnerability().getLastDetected().compareTo(e2.getVulnerability().getLastDetected());
                        }
                    });
                    Collections.sort(filteredTraces, new Comparator<ItemForVulnerability>() {
                        @Override
                        public int compare(ItemForVulnerability e1, ItemForVulnerability e2) {
                            return e1.getVulnerability().getLastDetected().compareTo(e2.getVulnerability().getLastDetected());
                        }
                    });
                }
                for (ItemForVulnerability vul : filteredTraces) {
                    addColToVulnTable(vul, -1);
                }
            }
        });
        TableColumn column4 = new TableColumn(traceTable, SWT.LEFT);
        column4.setWidth(300);
        column4.setText("脆弱性");
        TableColumn column5 = new TableColumn(traceTable, SWT.CENTER);
        column5.setWidth(120);
        column5.setText("重大度");
        column5.addListener(SWT.Selection, new Listener() {
            @Override
            public void handleEvent(Event event) {
                isSeveritySortDesc = !isSeveritySortDesc;
                traceTable.clearAll();
                traceTable.removeAll();
                if (isSeveritySortDesc) {
                    Collections.reverse(traces);
                    Collections.reverse(filteredTraces);
                } else {
                    Collections.sort(traces, new Comparator<ItemForVulnerability>() {
                        @Override
                        public int compare(ItemForVulnerability e1, ItemForVulnerability e2) {
                            SeverityEnum enum1 = SeverityEnum.valueOf(e1.getVulnerability().getSeverity());
                            SeverityEnum enum2 = SeverityEnum.valueOf(e2.getVulnerability().getSeverity());
                            return enum1.compareTo(enum2);
                        }
                    });
                    Collections.sort(filteredTraces, new Comparator<ItemForVulnerability>() {
                        @Override
                        public int compare(ItemForVulnerability e1, ItemForVulnerability e2) {
                            SeverityEnum enum1 = SeverityEnum.valueOf(e1.getVulnerability().getSeverity());
                            SeverityEnum enum2 = SeverityEnum.valueOf(e2.getVulnerability().getSeverity());
                            return enum1.compareTo(enum2);
                        }
                    });
                }
                for (ItemForVulnerability vul : filteredTraces) {
                    addColToVulnTable(vul, -1);
                }
            }
        });
        TableColumn column6 = new TableColumn(traceTable, SWT.CENTER);
        column6.setWidth(120);
        column6.setText("ステータス");
        TableColumn column7 = new TableColumn(traceTable, SWT.CENTER);
        column7.setWidth(120);
        column7.setText("保留中ステータス");
        TableColumn column8 = new TableColumn(traceTable, SWT.LEFT);
        column8.setWidth(300);
        column8.setText("アプリケーション");
        TableColumn column9 = new TableColumn(traceTable, SWT.LEFT);
        column9.setWidth(300);
        column9.setText("組織");

        Button traceFilterBtn = new Button(topComposite, SWT.PUSH);
        GridData traceFilterBtnGrDt = new GridData(GridData.FILL_HORIZONTAL);
        traceFilterBtnGrDt.horizontalSpan = 3;
        traceFilterBtn.setLayoutData(traceFilterBtnGrDt);
        traceFilterBtn.setText("フィルター");
        traceFilterBtn.setToolTipText("脆弱性のフィルタリングを行います。");
        traceFilterBtn.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                if (traceFilterMap == null) {
                    MessageDialog.openInformation(toolShell, "脆弱性フィルター", "脆弱性一覧を読み込んでください。");
                    return;
                }
                TraceFilterDialog filterDialog = new TraceFilterDialog(toolShell, traceFilterMap);
                filterDialog.addPropertyChangeListener(VulTabItem.this);
                int result = filterDialog.open();
                if (IDialogConstants.OK_ID != result) {
                    return;
                }
            }
        });

        Composite bottomComposite = new Composite(sashForm, SWT.NONE);
        bottomComposite.setLayout(new GridLayout(3, false));
        GridData bottomCompositeGrDt = new GridData(GridData.FILL_HORIZONTAL);
        bottomComposite.setLayoutData(bottomCompositeGrDt);

        sashForm.setWeights(new int[] { 75, 25 });

        subTabFolder = new CTabFolder(bottomComposite, SWT.NONE);
        GridData subTabFolderGrDt = new GridData(GridData.FILL_BOTH);
        subTabFolder.setLayoutData(subTabFolderGrDt);
        subTabFolder.setSelectionBackground(
                new Color[] { shell.getDisplay().getSystemColor(SWT.COLOR_WIDGET_BACKGROUND), shell.getDisplay().getSystemColor(SWT.COLOR_WIDGET_LIGHT_SHADOW) }, new int[] { 100 },
                true);
        subTabFolder.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
            }
        });
        addPropertyChangeListener(new VulSubOverviewTabItem(subTabFolder, toolShell, ps));
        addPropertyChangeListener(new VulSubDetailTabItem(subTabFolder, toolShell, ps));
        addPropertyChangeListener(new VulSubHttpinfoTabItem(subTabFolder, toolShell, ps));
        addPropertyChangeListener(new VulSubNoteTabItem(subTabFolder, toolShell, ps));
        int vul_subtab_idx = this.ps.getInt(PreferenceConstants.OPENED_VUL_SUBTAB_IDX);
        subTabFolder.setSelection(vul_subtab_idx);

        statusChangeBtn = new Button(vulnListGrp, SWT.PUSH);
        GridData statusChangeBtnGrDt = new GridData(GridData.FILL_HORIZONTAL);
        statusChangeBtnGrDt.horizontalSpan = 1;
        statusChangeBtnGrDt.heightHint = 36;
        statusChangeBtn.setLayoutData(statusChangeBtnGrDt);
        statusChangeBtn.setText("ステータス変更");
        statusChangeBtn.setToolTipText("選択されている脆弱性のステータスを変更します。");
        statusChangeBtn.setFont(new Font(toolShell.getDisplay(), "ＭＳ ゴシック", 15, SWT.BOLD));
        statusChangeBtn.setEnabled(false);
        statusChangeBtn.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent event) {
                StatusMarkDialog statusMarkDialog = new StatusMarkDialog(toolShell, ps);
                int result = statusMarkDialog.open();
                if (IDialogConstants.OK_ID != result) {
                    return;
                }
                StatusEnum statusEnum = statusMarkDialog.getStatus();
                SubStatusEnum subStatusEnum = statusMarkDialog.getSubStatus();
                String note = statusMarkDialog.getNote();
                Map<Organization, List<ItemForVulnerability>> targetMap = new HashMap<Organization, List<ItemForVulnerability>>();
                for (Organization org : toolShell.getMain().getValidOrganizations()) {
                    targetMap.put(org, new ArrayList<ItemForVulnerability>());
                }
                for (int idx : selectedIdxes) {
                    ItemForVulnerability vul = filteredTraces.get(idx);
                    targetMap.get(vul.getVulnerability().getOrg()).add(vul);
                }
                StatusMarkWithProgress progress = new StatusMarkWithProgress(toolShell, ps, targetMap, statusEnum, subStatusEnum, note);
                ProgressMonitorDialog progDialog = new StatusMarkProgressMonitorDialog(toolShell);
                try {
                    progDialog.run(true, true, progress);
                    List<ContrastJson> resJsonList = progress.getJsonList();
                    int successCnt = 0;
                    List<String> messageList = new ArrayList<String>();
                    for (ContrastJson contrastJson : resJsonList) {
                        if (Boolean.valueOf(contrastJson.getSuccess())) {
                            successCnt++;
                        }
                        messageList.addAll(contrastJson.getMessages());
                    }
                    MessageBox messageBox = null;
                    if (resJsonList.size() == successCnt) {
                        messageBox = new MessageBox(toolShell, SWT.ICON_INFORMATION | SWT.OK);
                        messageList.add("※ ステータスが更新されているので、確認する際は再取得をお願いいたします。");
                        messageBox.setMessage(String.join("\r\n", messageList));
                    } else if (successCnt > 0) {
                        messageBox = new MessageBox(toolShell, SWT.ICON_WARNING | SWT.OK);
                        messageList.add("※ ステータスが更新されているので、確認する際は再取得をお願いいたします。");
                        messageBox.setMessage(String.join("\r\n", messageList));
                    } else {
                        messageBox = new MessageBox(toolShell, SWT.ICON_ERROR | SWT.OK);
                        messageBox.setMessage(String.join("\r\n", messageList));
                    }
                    messageBox.setText("ステータス更新");
                    messageBox.open();
                } catch (InvocationTargetException e) {
                    StringWriter stringWriter = new StringWriter();
                    PrintWriter printWriter = new PrintWriter(stringWriter);
                    e.printStackTrace(printWriter);
                    String trace = stringWriter.toString();
                    logger.error(trace);
                    String errorMsg = e.getTargetException().getMessage();
                    if (e.getTargetException() instanceof ApiException) {
                        MessageDialog.openWarning(toolShell, "脆弱性一覧の取得", String.format("TeamServerからエラーが返されました。\r\n%s", errorMsg));
                    } else if (e.getTargetException() instanceof NonApiException) {
                        MessageDialog.openError(toolShell, "脆弱性一覧の取得", String.format("想定外のステータスコード: %s\r\nログファイルをご確認ください。", errorMsg));
                    } else {
                        MessageDialog.openError(toolShell, "脆弱性一覧の取得", String.format("不明なエラーです。ログファイルをご確認ください。\r\n%s", errorMsg));
                    }
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }

            }
        });

        approveBtn = new Button(vulnListGrp, SWT.PUSH);
        GridData approveBtnGrDt = new GridData(GridData.FILL_HORIZONTAL);
        approveBtnGrDt.horizontalSpan = 1;
        approveBtnGrDt.heightHint = 36;
        approveBtn.setLayoutData(approveBtnGrDt);
        approveBtn.setText("承認");
        approveBtn.setToolTipText("選択されている脆弱性のステータス変更を承認します。");
        approveBtn.setFont(new Font(toolShell.getDisplay(), "ＭＳ ゴシック", 15, SWT.BOLD));
        approveBtn.setEnabled(false);
        approveBtn.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent event) {
                Map<Organization, List<ItemForVulnerability>> targetMap = new HashMap<Organization, List<ItemForVulnerability>>();
                for (Organization org : toolShell.getMain().getValidOrganizations()) {
                    targetMap.put(org, new ArrayList<ItemForVulnerability>());
                }
                for (int idx : selectedIdxes) {
                    ItemForVulnerability vul = filteredTraces.get(idx);
                    targetMap.get(vul.getVulnerability().getOrg()).add(vul);
                }
                PendingStatusApprovalWithProgress progress = new PendingStatusApprovalWithProgress(toolShell, ps, targetMap, true);
                ProgressMonitorDialog progDialog = new PendingStatusApprovalProgressMonitorDialog(toolShell);
                try {
                    progDialog.run(true, true, progress);
                    List<PendingStatusApprovalJson> resJsonList = progress.getJsonList();
                    int successCnt = 0;
                    List<String> messageList = new ArrayList<String>();
                    for (PendingStatusApprovalJson contrastJson : resJsonList) {
                        if (Boolean.valueOf(contrastJson.getSuccess())) {
                            successCnt++;
                        }
                        messageList.addAll(contrastJson.getMessages());
                    }
                    MessageBox messageBox = null;
                    if (resJsonList.size() == successCnt) {
                        messageBox = new MessageBox(toolShell, SWT.ICON_INFORMATION | SWT.OK);
                        messageList.add("※ ステータスが更新されているので、確認する際は再取得をお願いいたします。");
                        messageBox.setMessage(String.join("\r\n", messageList));
                    } else if (successCnt > 0) {
                        messageBox = new MessageBox(toolShell, SWT.ICON_WARNING | SWT.OK);
                        messageList.add("※ ステータスが更新されているので、確認する際は再取得をお願いいたします。");
                        messageBox.setMessage(String.join("\r\n", messageList));
                    } else {
                        messageBox = new MessageBox(toolShell, SWT.ICON_ERROR | SWT.OK);
                        messageBox.setMessage(String.join("\r\n", messageList));
                    }
                    messageBox.setText("保留中ステータスの承認");
                    messageBox.open();
                } catch (InvocationTargetException e) {
                    StringWriter stringWriter = new StringWriter();
                    PrintWriter printWriter = new PrintWriter(stringWriter);
                    e.printStackTrace(printWriter);
                    String trace = stringWriter.toString();
                    logger.error(trace);
                    String errorMsg = e.getTargetException().getMessage();
                    if (e.getTargetException() instanceof ApiException) {
                        MessageDialog.openWarning(toolShell, "監査ログの取得", String.format("TeamServerからエラーが返されました。\r\n%s", errorMsg));
                    } else if (e.getTargetException() instanceof NonApiException) {
                        MessageDialog.openError(toolShell, "監査ログの取得", String.format("想定外のステータスコード: %s\r\nログファイルをご確認ください。", errorMsg));
                    } else {
                        MessageDialog.openError(toolShell, "監査ログの取得", String.format("不明なエラーです。ログファイルをご確認ください。\r\n%s", errorMsg));
                    }
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });

        rejectBtn = new Button(vulnListGrp, SWT.PUSH);
        GridData rejectBtnGrDt = new GridData();
        rejectBtnGrDt.horizontalSpan = 1;
        rejectBtnGrDt.heightHint = 36;
        rejectBtnGrDt.widthHint = 150;
        rejectBtn.setLayoutData(rejectBtnGrDt);
        rejectBtn.setText("拒否");
        rejectBtn.setToolTipText("選択されている脆弱性のステータス変更を拒否します。");
        rejectBtn.setFont(new Font(toolShell.getDisplay(), "ＭＳ ゴシック", 15, SWT.NORMAL));
        rejectBtn.setEnabled(false);
        rejectBtn.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent event) {
                PendingStatusRejectDialog rejectDialog = new PendingStatusRejectDialog(toolShell, ps);
                int result = rejectDialog.open();
                if (IDialogConstants.OK_ID != result) {
                    return;
                }
                String note = rejectDialog.getNote();
                Map<Organization, List<ItemForVulnerability>> targetMap = new HashMap<Organization, List<ItemForVulnerability>>();
                for (Organization org : toolShell.getMain().getValidOrganizations()) {
                    targetMap.put(org, new ArrayList<ItemForVulnerability>());
                }
                for (int idx : selectedIdxes) {
                    ItemForVulnerability vul = filteredTraces.get(idx);
                    targetMap.get(vul.getVulnerability().getOrg()).add(vul);
                }
                PendingStatusApprovalWithProgress progress = new PendingStatusApprovalWithProgress(toolShell, ps, targetMap, false, note);
                ProgressMonitorDialog progDialog = new PendingStatusApprovalProgressMonitorDialog(toolShell);
                try {
                    progDialog.run(true, true, progress);
                    List<PendingStatusApprovalJson> resJsonList = progress.getJsonList();
                    int successCnt = 0;
                    List<String> messageList = new ArrayList<String>();
                    for (PendingStatusApprovalJson contrastJson : resJsonList) {
                        if (Boolean.valueOf(contrastJson.getSuccess())) {
                            successCnt++;
                        }
                        messageList.addAll(contrastJson.getMessages());
                    }
                    MessageBox messageBox = null;
                    if (resJsonList.size() == successCnt) {
                        messageBox = new MessageBox(toolShell, SWT.ICON_INFORMATION | SWT.OK);
                        messageList.add("※ ステータスが更新されているので、確認する際は再取得をお願いいたします。");
                        messageBox.setMessage(String.join("\r\n", messageList));
                    } else if (successCnt > 0) {
                        messageBox = new MessageBox(toolShell, SWT.ICON_WARNING | SWT.OK);
                        messageList.add("※ ステータスが更新されているので、確認する際は再取得をお願いいたします。");
                        messageBox.setMessage(String.join("\r\n", messageList));
                    } else {
                        messageBox = new MessageBox(toolShell, SWT.ICON_ERROR | SWT.OK);
                        messageBox.setMessage(String.join("\r\n", messageList));
                    }
                    messageBox.setText("保留中ステータスの拒否");
                    messageBox.open();
                } catch (InvocationTargetException e) {
                    StringWriter stringWriter = new StringWriter();
                    PrintWriter printWriter = new PrintWriter(stringWriter);
                    e.printStackTrace(printWriter);
                    String trace = stringWriter.toString();
                    logger.error(trace);
                    String errorMsg = e.getTargetException().getMessage();
                    if (e.getTargetException() instanceof ApiException) {
                        MessageDialog.openWarning(toolShell, "監査ログの取得", String.format("TeamServerからエラーが返されました。\r\n%s", errorMsg));
                    } else if (e.getTargetException() instanceof NonApiException) {
                        MessageDialog.openError(toolShell, "監査ログの取得", String.format("想定外のステータスコード: %s\r\nログファイルをご確認ください。", errorMsg));
                    } else {
                        MessageDialog.openError(toolShell, "監査ログの取得", String.format("不明なエラーです。ログファイルをご確認ください。\r\n%s", errorMsg));
                    }
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });
        setControl(shell);
    }

    private void uiReset() {
        filteredTraces.clear();
        traceTable.clearAll();
        traceTable.removeAll();
        for (Button button : checkBoxList) {
            button.dispose();
        }
        checkBoxList.clear();
        support.firePropertyChange("uiReset", null, null);
    }

    private void detectedDateLabelUpdate() {
        if (frDetectedDate != null && toDetectedDate != null) {
            traceDetectedFilterTxt.setText(String.format("%s ～ %s", sdf.format(frDetectedDate), sdf.format(toDetectedDate)));
        } else if (frDetectedDate != null) {
            traceDetectedFilterTxt.setText(String.format("%s ～", sdf.format(frDetectedDate)));
        } else if (toDetectedDate != null) {
            traceDetectedFilterTxt.setText(String.format("～ %s", sdf.format(toDetectedDate)));
        } else {
            traceDetectedFilterTxt.setText("");
        }
    }

    private void addColToVulnTable(ItemForVulnerability vuln, int index) {
        if (vuln == null) {
            return;
        }
        TableEditor editor = new TableEditor(traceTable);
        Button button = new Button(traceTable, SWT.CHECK);
        button.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                selectedIdxes.clear();
                for (Button button : checkBoxList) {
                    if (button.getSelection()) {
                        selectedIdxes.add(checkBoxList.indexOf(button));
                    }
                }
                updateBtnStatus();
            }
        });
        button.pack();
        TableItem item = new TableItem(traceTable, SWT.CENTER);
        editor.minimumWidth = button.getSize().x;
        editor.horizontalAlignment = SWT.CENTER;
        editor.setEditor(button, item, 1);
        checkBoxList.add(button);
        item.setText(2, vuln.getVulnerability().getFirstDetectedStr());
        item.setText(3, vuln.getVulnerability().getLastDetectedStr());
        item.setText(4, vuln.getVulnerability().getTitle());
        item.setText(5, SeverityEnum.valueOf(vuln.getVulnerability().getSeverity()).getLabel());
        Optional<StatusEnum> status = StatusEnum.fromValue(vuln.getVulnerability().getStatus());
        status.ifPresentOrElse(s -> item.setText(6, s.getLabel()), () -> item.setText(6, ""));
        if (vuln.getVulnerability().getPendingStatus() != null) {
            Optional<StatusEnum> pendingStatus = StatusEnum.fromValue(vuln.getVulnerability().getPendingStatus().getStatus());
            pendingStatus.ifPresentOrElse(s -> item.setText(7, s.getLabel()), () -> item.setText(7, ""));
        }
        item.setText(8, vuln.getVulnerability().getApplication().getName());
        item.setText(9, vuln.getVulnerability().getOrg().getName());
    }

    public VulnTypeEnum getSelectedVulnType() {
        for (Map.Entry<VulnTypeEnum, Button> entry : vulnTypeBtnMap.entrySet()) {
            if (entry.getValue().getSelection()) {
                return entry.getKey();
            }
        }
        return VulnTypeEnum.ALL;
    }

    public DetectTypeEnum getSelectedDetectType() {
        for (Map.Entry<DetectTypeEnum, Button> entry : detectTypeBtnMap.entrySet()) {
            if (entry.getValue().getSelection()) {
                return entry.getKey();
            }
        }
        return DetectTypeEnum.FIRST;
    }

    private void updateBtnStatus() {
        boolean existUpdatableVul = false;
        boolean existApprovalVul = false;
        for (int idx : selectedIdxes) {
            ItemForVulnerability vul = filteredTraces.get(idx);
            if (vul.getVulnerability().getPendingStatus() == null) {
                existUpdatableVul |= true;
            } else {
                existApprovalVul |= true;
            }
        }
        statusChangeBtn.setEnabled(existUpdatableVul);
        approveBtn.setEnabled(existApprovalVul);
        rejectBtn.setEnabled(existApprovalVul);
    }

    private void updateTermFilterOption() {
        traceTermToday.setToolTipText(sdf.format(this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.TODAY)));
        traceTermYesterday.setToolTipText(sdf.format(this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.YESTERDAY)));
        traceTerm30days.setToolTipText(String.format("%s ～ %s", sdf.format(this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.BEFORE_30_DAYS)),
                sdf.format(this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.TODAY))));
        traceTermLastWeek.setToolTipText(String.format("%s ～ %s", sdf.format(this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.LAST_WEEK_START)),
                sdf.format(this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.LAST_WEEK_END))));
        traceTermThisWeek.setToolTipText(String.format("%s ～ %s", sdf.format(this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.THIS_WEEK_START)),
                sdf.format(this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.THIS_WEEK_END))));
        traceTermHalf1st.setToolTipText(String.format("%s ～ %s", sdf.format(this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.HALF_1ST_START)),
                sdf.format(this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.HALF_1ST_END))));
        traceTermHalf2nd.setToolTipText(String.format("%s ～ %s", sdf.format(this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.HALF_2ND_START)),
                sdf.format(traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.HALF_2ND_END))));
        detectedDateLabelUpdate();
    }

    private Date[] getFrToDetectedDate() {
        int idx = -1;
        for (Button termBtn : this.traceDetectedRadios) {
            if (termBtn.getSelection()) {
                idx = traceDetectedRadios.indexOf(termBtn);
                break;
            }
        }
        if (idx < 0) {
            idx = 0;
        }
        Date frDate = null;
        Date toDate = null;
        switch (idx) {
            case 0: // 上半期
                frDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.HALF_1ST_START);
                toDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.HALF_1ST_END);
                break;
            case 1: // 下半期
                frDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.HALF_2ND_START);
                toDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.HALF_2ND_END);
                break;
            case 2: // 30days
                frDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.BEFORE_30_DAYS);
                toDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.TODAY);
                break;
            case 3: // Yesterday
                frDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.YESTERDAY);
                toDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.YESTERDAY);
                break;
            case 4: // Today
                frDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.TODAY);
                toDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.TODAY);
                break;
            case 5: // LastWeek
                frDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.LAST_WEEK_START);
                toDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.LAST_WEEK_END);
                break;
            case 6: // ThisWeek
                frDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.THIS_WEEK_START);
                toDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.THIS_WEEK_END);
                break;
            case 7: // Specify
                if (frDetectedDate == null || toDetectedDate == null) {
                    return new Date[] {};
                }
                return new Date[] { frDetectedDate, toDetectedDate };
            default:
                frDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.BEFORE_30_DAYS);
                toDate = this.traceDetectedFilterMap.get(TraceDetectedDateFilterEnum.TODAY);
        }
        return new Date[] { frDate, toDate };
    }

    public Map<TraceDetectedDateFilterEnum, Date> getTraceDetectedDateMap() {
        Map<TraceDetectedDateFilterEnum, Date> map = new HashMap<TraceDetectedDateFilterEnum, Date>();
        LocalDate today = LocalDate.now();

        map.put(TraceDetectedDateFilterEnum.TODAY, Date.from(today.atStartOfDay(ZoneId.systemDefault()).toInstant()));
        map.put(TraceDetectedDateFilterEnum.YESTERDAY, Date.from(today.minusDays(1).atStartOfDay(ZoneId.systemDefault()).toInstant()));
        map.put(TraceDetectedDateFilterEnum.BEFORE_30_DAYS, Date.from(today.minusDays(30).atStartOfDay(ZoneId.systemDefault()).toInstant()));
        LocalDate lastWeekStart = today.with(TemporalAdjusters.previous(DayOfWeek.SUNDAY));
        lastWeekStart = lastWeekStart.minusDays(7 - ps.getInt(PreferenceConstants.START_WEEKDAY));
        if (lastWeekStart.plusDays(7).isAfter(today)) {
            lastWeekStart = lastWeekStart.minusDays(7);
        }
        map.put(TraceDetectedDateFilterEnum.LAST_WEEK_START, Date.from(lastWeekStart.atStartOfDay(ZoneId.systemDefault()).toInstant()));
        map.put(TraceDetectedDateFilterEnum.LAST_WEEK_END, Date.from(lastWeekStart.plusDays(6).atStartOfDay(ZoneId.systemDefault()).toInstant()));
        map.put(TraceDetectedDateFilterEnum.THIS_WEEK_START, Date.from(lastWeekStart.plusDays(7).atStartOfDay(ZoneId.systemDefault()).toInstant()));
        map.put(TraceDetectedDateFilterEnum.THIS_WEEK_END, Date.from(lastWeekStart.plusDays(13).atStartOfDay(ZoneId.systemDefault()).toInstant()));

        int termStartMonth = IntStream.range(0, OtherPreferencePage.MONTHS.length)
                .filter(i -> ps.getString(PreferenceConstants.TERM_START_MONTH).equals(OtherPreferencePage.MONTHS[i])).findFirst().orElse(-1);
        int half_1st_month_s = ++termStartMonth;
        int thisYear = today.getYear();
        // int thisMonth = today.getMonthValue(); // 元の仕様の場合はこのコメント解除
        // half 1st start
        LocalDate half_1st_month_s_date = null;
        // if (half_1st_month_s + 5 < thisMonth) { // 元の仕様の場合はこのコメント解除
        half_1st_month_s_date = LocalDate.of(thisYear, half_1st_month_s, 1);
        // } else { // 元の仕様の場合はこのコメント解除
        // half_1st_month_s_date = LocalDate.of(thisYear - 1, half_1st_month_s, 1); //
        // 元の仕様の場合はこのコメント解除
        // } // 元の仕様の場合はこのコメント解除
        map.put(TraceDetectedDateFilterEnum.HALF_1ST_START, Date.from(half_1st_month_s_date.atStartOfDay(ZoneId.systemDefault()).toInstant()));
        // half 1st end
        // LocalDate half_1st_month_e_date =
        // half_1st_month_s_date.plusMonths(6).minusDays(1);
        map.put(TraceDetectedDateFilterEnum.HALF_1ST_END, Date.from(half_1st_month_s_date.plusMonths(6).minusDays(1).atStartOfDay(ZoneId.systemDefault()).toInstant()));

        // half 2nd start
        LocalDate half_2nd_month_s_date = half_1st_month_s_date.plusMonths(6);
        // half 2nd end
        LocalDate half_2nd_month_e_date = half_2nd_month_s_date.plusMonths(6).minusDays(1);
        // int todayNum =
        // Integer.valueOf(today.format(DateTimeFormatter.ofPattern("yyyyMMdd"))); //
        // 元の仕様の場合はこのコメント解除
        // int termEndNum =
        // Integer.valueOf(half_2nd_month_e_date.format(DateTimeFormatter.ofPattern("yyyyMMdd")));
        // // 元の仕様の場合はこのコメント解除
        // if (todayNum < termEndNum) { // 元の仕様の場合はこのコメント解除
        // half_2nd_month_s_date = half_2nd_month_s_date.minusYears(1); //
        // 元の仕様の場合はこのコメント解除
        // half_2nd_month_e_date = half_2nd_month_e_date.minusYears(1); //
        // 元の仕様の場合はこのコメント解除
        // } // 元の仕様の場合はこのコメント解除
        map.put(TraceDetectedDateFilterEnum.HALF_2ND_START, Date.from(half_2nd_month_s_date.atStartOfDay(ZoneId.systemDefault()).toInstant()));
        map.put(TraceDetectedDateFilterEnum.HALF_2ND_END, Date.from(half_2nd_month_e_date.atStartOfDay(ZoneId.systemDefault()).toInstant()));
        return map;
    }

    @Override
    public void propertyChange(PropertyChangeEvent event) {
        if ("shellActivated".equals(event.getPropertyName())) {
            this.traceDetectedFilterMap = getTraceDetectedDateMap();
            Date[] frToDate = getFrToDetectedDate();
            if (frToDate.length > 1) {
                this.frDetectedDate = frToDate[0];
                this.toDetectedDate = frToDate[1];
                updateTermFilterOption();
            }
        } else if ("shellClosed".equals(event.getPropertyName())) {
            int sub_idx = subTabFolder.getSelectionIndex();
            ps.setValue(PreferenceConstants.OPENED_VUL_SUBTAB_IDX, sub_idx);
            ps.setValue(PreferenceConstants.VULN_CHOICE, getSelectedVulnType().name());
            ps.setValue(PreferenceConstants.DETECT_CHOICE, getSelectedDetectType().name());
            for (Button termBtn : traceDetectedRadios) {
                if (termBtn.getSelection()) {
                    ps.setValue(PreferenceConstants.TRACE_DETECTED_DATE_FILTER, traceDetectedRadios.indexOf(termBtn));
                }
            }
            if (traceTermPeriod.getSelection()) {
                ps.setValue(PreferenceConstants.DETECT_PERIOD, String.format("%s-%s", frDetectedDate.getTime(), toDetectedDate.getTime()));
            }
        } else if ("tabSelected".equals(event.getPropertyName())) {
        } else if ("buttonEnabled".equals(event.getPropertyName())) {
            traceLoadBtn.setEnabled((Boolean) event.getNewValue());
        } else if ("validOrgChanged".equals(event.getPropertyName())) {
            uiReset();
        } else if ("traceFilter".equals(event.getPropertyName())) {
            @SuppressWarnings("unchecked")
            Map<FilterEnum, Set<Filter>> filterMap = (Map<FilterEnum, Set<Filter>>) event.getNewValue();
            traceTable.clearAll();
            traceTable.removeAll();
            filteredTraces.clear();
            selectedIdxes.clear();
            for (Button button : checkBoxList) {
                button.dispose();
            }
            checkBoxList.clear();
            if (isFirstDetectSortDesc) {
                Collections.reverse(traces);
            } else {
                Collections.sort(traces, new Comparator<ItemForVulnerability>() {
                    @Override
                    public int compare(ItemForVulnerability e1, ItemForVulnerability e2) {
                        return e1.getVulnerability().getFirstDetected().compareTo(e2.getVulnerability().getFirstDetected());
                    }
                });
            }
            for (ItemForVulnerability vul : traces) {
                boolean lostFlg = false;
                for (Filter filter : filterMap.get(FilterEnum.RULE_NAME)) {
                    if (vul.getVulnerability().getRuleName().equals(filter.getLabel())) {
                        if (!filter.isValid()) {
                            lostFlg |= true;
                        }
                    }
                }
                for (Filter filter : filterMap.get(FilterEnum.SEVERITY)) {
                    if (vul.getVulnerability().getSeverity().equals(filter.getKeycode())) {
                        if (!filter.isValid()) {
                            lostFlg |= true;
                        }
                    }
                }
                for (Filter filter : filterMap.get(FilterEnum.APP_NAME)) {
                    if (vul.getVulnerability().getApplication().getName().equals(filter.getLabel())) {
                        if (!filter.isValid()) {
                            lostFlg |= true;
                        }
                    }
                }
                for (Filter filter : filterMap.get(FilterEnum.ORG_NAME)) {
                    if (vul.getVulnerability().getOrg().getName().equals(filter.getLabel())) {
                        if (!filter.isValid()) {
                            lostFlg |= true;
                        }
                    }
                }
                for (Filter filter : filterMap.get(FilterEnum.STATUS)) {
                    if (vul.getVulnerability().getStatus().equals(filter.getKeycode())) {
                        if (!filter.isValid()) {
                            lostFlg |= true;
                        }
                    }
                }
                for (Filter filter : filterMap.get(FilterEnum.PENDING_STATUS)) {
                    if (vul.getVulnerability().getPendingStatus() != null && vul.getVulnerability().getPendingStatus().getStatus().equals(filter.getKeycode())) {
                        if (!filter.isValid()) {
                            lostFlg |= true;
                        }
                    }
                }
                if (!lostFlg) {
                    addColToVulnTable(vul, -1);
                    filteredTraces.add(vul);
                }
            }
            traceCount.setText(String.format("%d/%d", filteredTraces.size(), traces.size()));
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
