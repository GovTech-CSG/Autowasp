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
package autowasp.logger.instancesTable;

import autowasp.Autowasp;

import javax.swing.DefaultCellEditor;
import javax.swing.JComboBox;
import javax.swing.JTable;
import javax.swing.table.TableColumn;
import javax.swing.table.TableModel;

@SuppressWarnings("serial")
public class InstanceTable extends JTable {
	private final Autowasp extender;
	private int currentRow;

	public InstanceTable(TableModel tableModel, Autowasp extender){
        super(tableModel);
		this.extender = extender;
		setColumnWidths(50, 80, 2500, 350, 150, 300, 150, Integer.MAX_VALUE);
	}

	public void setColumnWidths(int... widths) {
		for (int i = 0; i < widths.length; i += 2) {
			if ((i / 2) < columnModel.getColumnCount()) {
				columnModel.getColumn(i / 2).setPreferredWidth(widths[i]);
				columnModel.getColumn(i / 2).setMaxWidth(widths[i + 1]);
			}
			else continue;
		}
	}

	// Method for table view change selection
	@Override
	public void changeSelection(int row, int col, boolean toggle, boolean extend){
	    // show the log entry for the selected row
		currentRow = row;
		InstanceEntry instanceEntry = extender.instanceLog.get(row);
		if (instanceEntry.isIHttpRequestResponseNull()) {
			String toPrint = "";
			byte[] toByte = toPrint.getBytes();
	    	extender.extenderPanelUI.requestViewer.setMessage(toByte, false);
	    	extender.extenderPanelUI.responseViewer.setMessage(toByte, false);
		}
		else {
	    	extender.extenderPanelUI.requestViewer.setMessage(instanceEntry.requestResponse.getRequest(), true);
	    	extender.extenderPanelUI.responseViewer.setMessage(instanceEntry.requestResponse.getResponse(), true);
		}
	    super.changeSelection(row, col, toggle, extend);
		extender.extenderPanelUI.deleteInstanceButtonEnabled();
	}

	// Method to setup confidence column with dropdown combo
	public void setUpConfidenceColumn(TableColumn column) {
		DefaultCellEditor dce = new DefaultCellEditor(extender.comboBox2);
		column.setCellEditor(dce);
	}

	// Method to setup Severity column with dropdown combo
	public void setupSeverityColumn(TableColumn column) {
		DefaultCellEditor dce = new DefaultCellEditor(extender.comboBox3);
		column.setCellEditor(dce);
	}

	// Method to prepare confidence dropdown combo
	public void generateConfidenceList() {
    	JComboBox<String> comboBox = extender.comboBox2;
		comboBox.addItem("False Positive");
		comboBox.addItem("Certain");
		comboBox.addItem("Firm");
		comboBox.addItem("Tentative");
	}

	// Method to prepare severity dropdown combo
	public void generateSeverityList() {
		JComboBox<String> comboBox = extender.comboBox3;
		comboBox.addItem("High");
		comboBox.addItem("Medium");
		comboBox.addItem("Low");
		comboBox.addItem("Information");
	}

	// Method to delete instance
	public void deleteInstance(){
		// delete instance
		extender.extenderPanelUI.deleteInstanceButton.setEnabled(false);
		extender.loggerList.get(extender.currentEntryRow).getInstanceList().remove(currentRow);
		// update UI
		// If there are remaining instances
		if (extender.loggerList.get(extender.currentEntryRow).getInstanceList().size() != 0){
			// Inform user about instance deletion
			extender.extenderPanelUI.scanStatusLabel.setText("Instance deleted");
			extender.callbacks.issueAlert("Instance deleted");
			// Repaint instances table
			extender.instancesTableModel.clearInstanceEntryList();
			extender.instancesTableModel.addAllInstanceEntry(extender.loggerList.get(extender.currentEntryRow).instancesList);
		}
		// Else, no more instances left in entry
		else{
			// delete entries instead
			extender.loggerTable.deleteEntry();
		}
	}

}