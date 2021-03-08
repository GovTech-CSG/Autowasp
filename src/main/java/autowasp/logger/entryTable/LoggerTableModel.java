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
import javax.swing.table.AbstractTableModel;
import java.util.List;

@SuppressWarnings("serial")
public class LoggerTableModel extends AbstractTableModel{
	private final List<LoggerEntry> listFindingEntry;
    private final String[] columnNames = { "#", "Host", "Action", "Vuln Type", "Mapped to OWASP WSTG" };
	
	public LoggerTableModel(List<LoggerEntry> listFindingEntry) {
		this.listFindingEntry = listFindingEntry;
	}

	// Method to get column count
	@Override
	public int getColumnCount() {
		return columnNames.length;
	}

	// Method to get row count
	@Override
	public int getRowCount() {
		return listFindingEntry.size();
	}

	// Method to get column name
	public String getColumnName(int columnIndex) {
        return columnNames[columnIndex];
	}

	// Method to get value at selected row and column
	@Override
	public String getValueAt(int rowIndex, int columnIndex) {
		String returnValue = "";
		LoggerEntry loggerEntry = listFindingEntry.get(rowIndex);
		switch (columnIndex) {
			case 0:
				returnValue = rowIndex + 1 + "";
				break;
			case 1:
				returnValue = loggerEntry.host;
				break;
			case 2:
				returnValue = loggerEntry.action;
				break;
			case 3:
				returnValue = loggerEntry.vulnType;
				break;
			case 4:
				returnValue = loggerEntry.checklistIssue;
				break;
		}
		return returnValue;
	}

	// Method to set value at selected row and column
	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		LoggerEntry loggerEntry = listFindingEntry.get(rowIndex);
		if (columnIndex == 4) {
			loggerEntry.setChecklistIssue((String) aValue);
		}
	}

	// Method to clear instance entry from table view
	public void clearLoggerList() {
		this.listFindingEntry.clear();
	}

	// Method to re-add all entry from existing list to table view
	public void addAllLoggerEntry(LoggerEntry loggerEntry) {
		this.listFindingEntry.add(loggerEntry);
		this.fireTableDataChanged();
	}

	// Method to update entry in table view
	public void updateLoggerEntryTable() {
		this.fireTableDataChanged();
	}

	// Method to restrict editable cell to those with dropdown combo.
	public boolean isCellEditable(int row, int col) {
		return col == 4;
	}
}
