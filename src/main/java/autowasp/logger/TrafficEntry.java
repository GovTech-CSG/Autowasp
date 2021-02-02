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

import autowasp.http.HTTPRequestResponse;

import java.net.URL;

public class TrafficEntry {

	public final String flag;
	public final HTTPRequestResponse requestResponse;
	public final URL url;
	public final TrafficInstance affectedInstancesList;
	public final String evidence;
	public final String trafficMsg;
	
	TrafficEntry(String flag, HTTPRequestResponse requestResponse, URL url, TrafficInstance affectedInstancesList, String evidence, String trafficMsg){
		this.flag = flag;
		this.requestResponse = requestResponse;
		this.url = url;
		this.affectedInstancesList = affectedInstancesList;
		this.evidence = evidence;
		this.trafficMsg = trafficMsg;
	}
}
