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
package autowasp.logger.entryTable;

import autowasp.logger.instancesTable.InstanceEntry;

import java.io.Serializable;
import java.util.ArrayList;

public class LoggerEntry implements Serializable {
	
	public final String host;
	public final String action;
	public final String vulnType;
	public String checklistIssue;
	public final ArrayList<InstanceEntry> instancesList;
	public String penTesterComments;
	public String evidences;
	public final Integer issueNumber; //Points to the test case in the OWASP checklist that the user maps this particular finding to
	
	public LoggerEntry(String host, String action, String vulnType, String checklistIssue){
		this.host = host;
		this.action = action;
		this.vulnType = vulnType;
		this.checklistIssue = checklistIssue;
		this.issueNumber = null;
		instancesList = new ArrayList<>();
		penTesterComments = "Please insert comments";
		evidences = "nil";
	}
	
	public LoggerEntry(String host, String action, String vulnType, String checklistIssue, String comments){
		this.host = host;
		this.action = action;
		this.vulnType = vulnType;
		this.checklistIssue = checklistIssue;
		this.issueNumber = null;
		instancesList = new ArrayList<>();
		penTesterComments = comments;
		evidences = "Please insert evidences";
	}

	public String getHost(){ return this.host;}

	public String getChecklistIssue() {
		return this.checklistIssue;
	}
	
	public void setChecklistIssue(String checklistIssue) {
		this.checklistIssue = checklistIssue;
	}
	
	public void setPenTesterComments(String penTesterComments) {
		this.penTesterComments = penTesterComments;
	}
	
	public String getPenTesterComments() {
		return this.penTesterComments;
	}
	
	public void setEvidence(String evidence) {
		this.evidences = evidence;
	}
	
	public String getEvidence() {
		return this.evidences;
	}
	
	public ArrayList<InstanceEntry> getInstanceList() {
		return this.instancesList;
	}
	
	public void addInstance(InstanceEntry instance) {
		this.instancesList.add(instance);
	}

	public int getIssueNumber() {
		return this.issueNumber;
	}

	public String getVulnType() {
		return vulnType;
	}

	public String toString() {
		return "host: " + this.host +  ";action: " + this.action + ";issue: " + this.checklistIssue;
	}
}
