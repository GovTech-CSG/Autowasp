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

package autowasp.logger.instancesTable;

import autowasp.http.HTTPRequestResponse;
import burp.IHttpRequestResponse;

import java.io.Serializable;
import java.net.URL;

public class InstanceEntry implements Serializable {
	public int id = 0;
	public final URL url;
	public String confidence;
	public String severity;
	public final HTTPRequestResponse requestResponse;
	final boolean falsePositive;
	
	public InstanceEntry(URL url, String confidence, String severity, HTTPRequestResponse requestResponse){
		this.id = this.id + 1;
		this.url = url;
		this.confidence = confidence;
		this.severity = severity;
		this.requestResponse = requestResponse;
		this.falsePositive = false;
	}

	
	public void setConfidence(String confidence) {
		this.confidence = confidence;
	}
	
	public String getConfidence() {
		return this.confidence;
	}

	public void setSeverity(String severity) {
		this.severity = severity;
	}

	public String getSeverity() {
		return severity;
	}


	public IHttpRequestResponse getResReq() {
		return this.requestResponse;
	}
	
	public boolean isIHttpRequestResponseNull() {
		return this.requestResponse == null;
	}

	public String getUrl() {
		return url.toString();
	}
}
