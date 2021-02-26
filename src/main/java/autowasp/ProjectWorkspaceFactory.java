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

package autowasp;

import autowasp.logger.entryTable.LoggerEntry;

import java.io.*;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;

public class ProjectWorkspaceFactory implements Serializable {
	private final Autowasp extender;
	
	public ProjectWorkspaceFactory(Autowasp extender){
		this.extender = extender;
	}

	// Method to save project to file directory
	public void saveFile(String absoluteFilePath) throws IOException {
		FileOutputStream fileOutputStream = null;
		try{
			fileOutputStream = new FileOutputStream(absoluteFilePath + File.separator + "autowasp_project.ser");
			ObjectOutputStream outputStream = new ObjectOutputStream(fileOutputStream);
			for (LoggerEntry loggerEntry : extender.loggerList) {
				outputStream.writeObject(loggerEntry);
			}
			outputStream.close();
			extender.extenderPanelUI.scanStatusLabel.setText("File saved to " + absoluteFilePath + File.separator + "autowasp_project.ser");
			extender.callbacks.issueAlert("File saved to " + absoluteFilePath + File.separator + "autowasp_project.ser");
		}
		finally {
			if (fileOutputStream !=null){
				safeClose(fileOutputStream);
			}
		}
	}

	// Method to obtain file directory
	public void readFromFile(String absoluteFilePath) {
		boolean eof = false;
		LoggerEntry loggerEntryTemp;
		extender.loggerTableModel.clearLoggerList();
		List<LoggerEntry> loggerEntryList = new List<LoggerEntry>() {
			@Override
			public int size() {
				return 0;
			}

			@Override
			public boolean isEmpty() {
				return false;
			}

			@Override
			public boolean contains(Object o) {
				return false;
			}

			@Override
			public Iterator<LoggerEntry> iterator() {
				return null;
			}

			@Override
			public Object[] toArray() {
				return new Object[0];
			}

			@Override
			public <T> T[] toArray(T[] a) {
				return null;
			}

			@Override
			public boolean add(LoggerEntry loggerEntry) {
				return false;
			}

			@Override
			public boolean remove(Object o) {
				return false;
			}

			@Override
			public boolean containsAll(Collection<?> c) {
				return false;
			}

			@Override
			public boolean addAll(Collection<? extends LoggerEntry> c) {
				return false;
			}

			@Override
			public boolean addAll(int index, Collection<? extends LoggerEntry> c) {
				return false;
			}

			@Override
			public boolean removeAll(Collection<?> c) {
				return false;
			}

			@Override
			public boolean retainAll(Collection<?> c) {
				return false;
			}

			@Override
			public void clear() {

			}

			@Override
			public LoggerEntry get(int index) {
				return null;
			}

			@Override
			public LoggerEntry set(int index, LoggerEntry element) {
				return null;
			}

			@Override
			public void add(int index, LoggerEntry element) {

			}

			@Override
			public LoggerEntry remove(int index) {
				return null;
			}

			@Override
			public int indexOf(Object o) {
				return 0;
			}

			@Override
			public int lastIndexOf(Object o) {
				return 0;
			}

			@Override
			public ListIterator<LoggerEntry> listIterator() {
				return null;
			}

			@Override
			public ListIterator<LoggerEntry> listIterator(int index) {
				return null;
			}

			@Override
			public List<LoggerEntry> subList(int fromIndex, int toIndex) {
				return null;
			}
		};
		FileInputStream fileInputStream = null;
		try {
			fileInputStream = new FileInputStream(absoluteFilePath);
			ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);

			while(!eof){
				try {
					loggerEntryTemp = (LoggerEntry) objectInputStream.readObject();
					loggerEntryList.add(loggerEntryTemp);
					extender.loggerTableModel.addAllLoggerEntry(loggerEntryTemp);
					extender.scannerLogic.repeatedIssue.add(loggerEntryTemp.getVulnType());
				} catch (EOFException e) {
					eof = true;
				}
			}
			objectInputStream.close();
		} catch (FileNotFoundException e){
			extender.stdout.println("File not found");
		} catch (IOException e){
			extender.stdout.println("Cannot read file");
		} catch (ClassNotFoundException e)
		{
			extender.stdout.println("LoggerEntry class not found");
		}
		finally {
			if (fileInputStream != null){
				safeClose(fileInputStream);
			}
		}
	}

	// Method for save closing of FileOutputStream
	public  void safeClose(FileOutputStream fos) {
		if (fos != null) {
			try {
				fos.close();
			} catch (IOException e) {
				extender.stdout.println("FileOutputStream cannot safe close");
			}
		}
	}

	// Method for save closing of FileInputStream
	public  void safeClose(FileInputStream fis) {
		if (fis != null) {
			try {
				fis.close();
			} catch (IOException e) {
				extender.stdout.println("FileInputStream cannot safe close");
			}
		}
	}
}
