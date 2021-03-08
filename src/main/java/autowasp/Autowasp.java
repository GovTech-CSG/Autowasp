/*
 * Copyright (c) 2021 Government Technology Agency
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package autowasp;

import autowasp.checklist.*;
import autowasp.http.*;
import autowasp.logger.ScannerLogic;
import autowasp.logger.TrafficEntry;
import autowasp.logger.TrafficLogic;
import autowasp.logger.entryTable.LoggerEntry;
import autowasp.logger.entryTable.LoggerTable;
import autowasp.logger.entryTable.LoggerTableModel;
import autowasp.logger.instancesTable.InstanceEntry;
import autowasp.logger.instancesTable.InstanceTable;
import autowasp.logger.instancesTable.InstancesTableModel;
import burp.*;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

public class Autowasp implements IBurpExtender, ITab, IMessageEditorController, IScannerListener, IProxyListener {
    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    public IBurpCollaboratorClientContext iBurpCollaboratorClientContext;
    public PrintWriter stdout;
    public PrintWriter stderr;
    public TrafficLogic trafficLogic;
    public ExtenderPanelUI extenderPanelUI;
    public JSplitPane gtScannerSplitPane;
    public ChecklistLogic checklistLogic;
    public ChecklistTableModel checklistTableModel;
    public ChecklistTable checklistTable;
    public final List<ChecklistEntry> checklistLog = new ArrayList<>();
    public final HashMap<String, ChecklistEntry> checkListHashMap = new HashMap<>();
    public final List<TrafficEntry> trafficLog = new ArrayList<>();
    public LoggerTableModel loggerTableModel;
    public InstancesTableModel instancesTableModel;
    public LoggerTable loggerTable;
    public InstanceTable instanceTable;
    public final List<LoggerEntry> loggerList = new ArrayList<>();
    public final List<InstanceEntry> instanceLog = new ArrayList<>();
    public ScannerLogic scannerLogic;
    public  ProjectWorkspaceFactory projectWorkspace;
    public JComboBox<String> comboBox;
    public JComboBox<String> comboBox2;
    public JComboBox<String> comboBox3;
    public int currentEntryRow;

    // Implementing IBurpExtender
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callback object
        this.callbacks = callbacks;

        // obtain iBurpCollaborator object
        this.iBurpCollaboratorClientContext = callbacks.createBurpCollaboratorClientContext();

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("Autowasp");

        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        this.extenderPanelUI = new ExtenderPanelUI(this);

        // Initialize variables for logger features
        this.instancesTableModel = new InstancesTableModel(instanceLog);
        this.instanceTable = new InstanceTable(instancesTableModel, this);

        this.loggerTableModel = new LoggerTableModel(loggerList);
        this.loggerTable = new LoggerTable(loggerTableModel, this);

        this.scannerLogic = new ScannerLogic(this);
        this.trafficLogic = new TrafficLogic(this);

        // Initialize variables for OWASP checklist feature
        this.checklistLogic = new ChecklistLogic(this);
        this.checklistTableModel = new ChecklistTableModel(this);
        this.checklistTable = new ChecklistTable(checklistTableModel, this);

        // Saving project state feature
        this.projectWorkspace = new ProjectWorkspaceFactory(this);

        // Create our IContextMenu
        // IContextMenu
        ContextMenuFactory contextMenu = new ContextMenuFactory(this);
        this.callbacks.registerContextMenuFactory(contextMenu);

        // Bind Issue ComboBox to loggerTable column number 5
        this.comboBox = new JComboBox<>();
        this.loggerTable.setUpIssueColumn(loggerTable.getColumnModel().getColumn(4));

        // Bind Confidence ComboBox to instanceTable column number 2
        this.comboBox2 = new JComboBox<>();
        this.instanceTable.generateConfidenceList();
        instanceTable.setUpConfidenceColumn(instanceTable.getColumnModel().getColumn(2));

        // Bind Severity ComboBox in instanceTable column number 3
        this.comboBox3 = new JComboBox<>();
        this.instanceTable.generateSeverityList();
        instanceTable.setupSeverityColumn(instanceTable.getColumnModel().getColumn(3));

        // create our UI
        SwingUtilities.invokeLater(() -> {
            extenderPanelUI.run();
            callbacks.registerProxyListener(Autowasp.this);

            // customize our UI components
            callbacks.customizeUiComponent(gtScannerSplitPane);

            // add the custom tab to Burp's UI
            callbacks.addSuiteTab(Autowasp.this);
        });
    }

    // implement ITab
    @Override
    public String getTabCaption(){
        return "Autowasp";
    }

    @Override
    public Component getUiComponent() {
        return gtScannerSplitPane;
    }

    @Override
    public void newScanIssue(IScanIssue Iissue) {
        ScanIssue issue = new ScanIssue(Iissue);
        if (this.callbacks.isInScope(issue.getUrl()) && !this.scannerLogic.getRepeatedIssue().contains(issue.getIssueName())){
            this.scannerLogic.getRepeatedIssue().add(issue.getIssueName());
            callbacks.issueAlert("New Scan found " + issue.getIssueName());
            // 1. Create a new finding record
            scannerLogic.logNewScan(issue);
            // 2. Log this instance
            scannerLogic.logNewInstance(issue);
        }
        else if (this.callbacks.isInScope(issue.getUrl()) && this.scannerLogic.getRepeatedIssue().contains(issue.getIssueName())) {
            // Identify the finding record is created and log the instance
            scannerLogic.logNewInstance(issue);
        }
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        try {
            InterceptProxyMessage interceptProxyMessage = new InterceptProxyMessage(message);
            URL url = new URL(message.getMessageInfo().getHttpService().toString());
            if (callbacks.isInScope(url)){
                if (!messageIsRequest) {
                    synchronized (trafficLog) {
                        trafficLogic.classifyTraffic(interceptProxyMessage);
                    }
                }
            }
        } catch (MalformedURLException e) {
            stdout.println("MalformedURLException at processProxyMessage()");
        }
    }

    @Override
    public IHttpService getHttpService() {
        return null;
    }

    @Override
    public byte[] getRequest() {
        return new byte[0];
    }

    @Override
    public byte[] getResponse() {
        return new byte[0];
    }
}