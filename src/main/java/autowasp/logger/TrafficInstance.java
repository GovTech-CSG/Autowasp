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

package autowasp.logger;

public class TrafficInstance {
	
	public boolean isUnencrypted;
	public boolean isBase64;
	public boolean isXContent;
	public final boolean isServerInfoLeaked;
	public boolean isServerErrorInfoLeaked;
	public boolean isCorHeaders;
	public final boolean isUnauthorisedDisclosure;
	public final boolean isXSS;
	public boolean isCGI;
	public boolean isHTTPVerb;
	
	public TrafficInstance(){
		this.isUnencrypted = false;
		this.isBase64 = false;
		this.isXContent = false;
		this.isServerInfoLeaked = false;
		this.isServerErrorInfoLeaked = false;
		this.isCorHeaders = false;
		this.isUnauthorisedDisclosure = false;
		this.isXSS = false;
		this.isCGI = false;
		this.isHTTPVerb = false;
	}
	
	public void setUnencrypted() {
		this.isUnencrypted = true;
	}
	
	public void setServerInfoLeaked() {
		this.isServerErrorInfoLeaked = true;
	}
	
	public void setServerErrorInfoLeaked() {
		this.isServerErrorInfoLeaked = true;
	}
	
	public void setCGI() {
		this.isCGI = true;
	}
	
	public void setBase64() {
		this.isBase64 = true;
	}
	
	public void setCorHeaders() {
		this.isCorHeaders = true;
	}
	
	public void setHttpVerb() {
		this.isHTTPVerb = true;
	}
	
	public void setXContentHeaders() {
		this.isXContent = true;
	}
}