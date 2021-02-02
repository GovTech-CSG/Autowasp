/*
 * Copyright (c) 2020 Government Technology Agency
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

package autowasp.logger;

import autowasp.Autowasp;
import autowasp.http.HTTPRequestResponse;
import autowasp.http.ScanIssue;
import autowasp.logger.entryTable.LoggerEntry;
import autowasp.logger.instancesTable.InstanceEntry;
import burp.IScanIssue;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import java.net.URL;
import java.util.ArrayList;


public class 	ScannerLogic {
	private final Autowasp extender;
	public final ArrayList<String> repeatedIssue;

	public ArrayList<String> getRepeatedIssue() {
		return repeatedIssue;
	}

	public ScannerLogic(Autowasp extender) {
		this.extender = extender;
		this.repeatedIssue = new ArrayList<>();
	}

	// Method to extract existing scan results
	public void extractExistingScan() {
		boolean newEntryFlag = true;
		IScanIssue[] scannedIssues = this.extender.callbacks.getScanIssues("http");
		for(IScanIssue iScanIssue:scannedIssues) {
			ScanIssue issue = castIScanToScan(iScanIssue);
			String issueHost = issue.getHttpService().getHost();
			String vulnType = issue.getIssueName();
			if (this.extender.callbacks.isInScope(issue.getUrl())) {
				// If issue is new and not in repeated list
				if (!this.repeatedIssue.contains(issue.getIssueName())) {
					logNewScan(issue);
					this.repeatedIssue.add(issue.getIssueName());
					logNewInstance(issue);
				} else {
					for (LoggerEntry entry : this.extender.loggerList) {
						// check if the issue.host and issue.vulnType is equal
						if (entry.getHost().equals(issueHost) && entry.getVulnType().equals(vulnType)) {
							logNewInstance(issue);
							newEntryFlag = false;
						}
					}
					// else new entry.
					if (newEntryFlag) {
						logNewScan(issue);
						logNewInstance(issue);
					}
				}
			}
		}
		extender.callbacks.registerScannerListener(extender);
	}

	public ScanIssue castIScanToScan(IScanIssue iScanIssue){
		ScanIssue scanIssue = new ScanIssue(iScanIssue);
		return scanIssue;
	}

	// Method to log new instance to a particular issue
	public void logNewInstance(ScanIssue issue) {
		// form up instances information
		URL url = issue.getUrl();
		String confidence = issue.getConfidence();
		String severity = issue.getSeverity();
		HTTPRequestResponse requestResponse = null;

		if(issue.getHttpMessages() != null && issue.getHttpMessages().length !=0) {
			requestResponse = issue.getHttpMessages()[0];
		}
		InstanceEntry instance = new InstanceEntry(url, confidence, severity, requestResponse);
		String issueHost = issue.getHttpService().getHost();
		String issueVulnType = issue.getIssueName();

		for (LoggerEntry entry : this.extender.loggerList) {
			if (entry.getHost().equals(issueHost) && entry.getVulnType().equals(issueVulnType)) {
				boolean toAddFlag = true;
				for (InstanceEntry ie: entry.getInstanceList()){
					// check if instanceList contain similar URL.
					if (ie.getUrl().equals(url.toString())) {
						// if url is not unique, set toAddFlag to false
						toAddFlag = false;
					}
				}
				// add new instance if toAddFlag is true
				if (toAddFlag) {
					entry.addInstance(instance);
				}
			}
		}
	}

	// Method to log new scan entry
	public void logNewScan(ScanIssue issue) {
		// Form scan issue information
		String host = issue.getHttpService().getHost();
		String action = "Burp Scanner";
		String issueName = "";
		String vulnType = issue.getIssueName();
		String defaultComments = "Burp Scanner detected the following issue type: " + issue.getIssueName();
		String evidences = issue.getIssueDetail();
		if (evidences == null){
			evidences = "Refer to affected instances Request and Response.";
		}
		Document document = Jsoup.parse(evidences);
		evidences = document.text();

		LoggerEntry entry = new LoggerEntry(host, action, vulnType, issueName);
		entry.instancesList.clear();
		entry.setPenTesterComments(defaultComments);
		entry.setEvidence(evidences);
		extender.loggerTableModel.addAllLoggerEntry(entry);
	}

}
