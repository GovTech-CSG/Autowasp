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

package autowasp.http;

import autowasp.Autowasp;
import autowasp.logger.entryTable.LoggerEntry;
import autowasp.logger.instancesTable.InstanceEntry;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;

import javax.swing.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class ContextMenuFactory implements IContextMenuFactory {

    private HTTPRequestResponse[] requestResponseArr;
    private ContextMenuInvocation contextMenuInvocation;
    private Autowasp extender;

    public ContextMenuFactory(Autowasp autowasp){
        this.extender = autowasp;
    }

    // Method to create Menu context items. Currently allow users to send request/response from proxy and repeater tab
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        this.contextMenuInvocation = new ContextMenuInvocation(invocation);
        ArrayList<JMenuItem> menu = new ArrayList<>();
        byte ctx = contextMenuInvocation.getInvocationContext();
        JMenuItem item;

        // Context menu for proxy tab
        if (ctx == ContextMenuInvocation.CONTEXT_PROXY_HISTORY) {
            this.requestResponseArr = contextMenuInvocation.getSelectedMessages();
            item = new JMenuItem("Send proxy finding to Autowasp", null);
            item.addActionListener(e -> {
                String action = "Sent from Proxy History";
                String comments = requestResponseArr[0].getComment();
                logToAutowasp(action, comments);
            });
            menu.add(item);
        }
        // Context menu for repeater tab
        else if ((ctx == ContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) &&
                (contextMenuInvocation.getToolFlag() == 64)){
            this.requestResponseArr = contextMenuInvocation.getSelectedMessages();
            item = new JMenuItem("Send repeater finding to Autowasp", null);
            item.addActionListener(actionEvent -> {
                String action = "Sent from Repeater";
                String comments = requestResponseArr[0].getComment();
                logToAutowasp(action, comments);
            });
            menu.add(item);
        }
        // Context menu for intruder tab
        else if(ctx == ContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS){
            this.requestResponseArr = contextMenuInvocation.getSelectedMessages();
            item = new JMenuItem("Send intruder finding to Autowasp", null);
            item.addActionListener(actionEvent -> {
                String action = "Sent from Intruder";
                String comments = requestResponseArr[0].getComment();
                logToAutowasp(action, comments);
            });
            menu.add(item);
        }
        return menu;
    }

    // Method to log finding(s) to Autowasp
    private void logToAutowasp(String action, String comments) {
        String host = requestResponseArr[0].getHttpService().getHost();

        String port = String.valueOf(requestResponseArr[0].getHttpService().getPort());

        String vulnType = "~";
        String issue = "";
        LoggerEntry findingEntry = new LoggerEntry(host, action, vulnType, issue, comments);
        String confidence = "";
        String severity = "~";

        for (HTTPRequestResponse iHttpRequestResponse : requestResponseArr) {
            URL url = extender.helpers.analyzeRequest(iHttpRequestResponse).getUrl();
            extender.callbacks.issueAlert("URL = " + url.toString());

            InstanceEntry instanceEntry = new InstanceEntry(url, confidence, severity, iHttpRequestResponse);
            findingEntry.addInstance(instanceEntry);
        }
        extender.loggerTableModel.addAllLoggerEntry(findingEntry);
    }

}
