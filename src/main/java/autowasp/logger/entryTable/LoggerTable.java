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

import autowasp.Autowasp;
import autowasp.checklist.ChecklistEntry;

import javax.swing.DefaultCellEditor;
import javax.swing.JComboBox;
import javax.swing.JTable;
import javax.swing.table.TableColumn;
import javax.swing.table.TableModel;

@SuppressWarnings("serial")
public class LoggerTable extends JTable {
	private final Autowasp extender;
	private int currentRow;
	
	public LoggerTable(TableModel tableModel, Autowasp extender){
        super(tableModel);
		this.extender = extender;
		setColumnWidths(50, 50, 150, 300, 150, 300, 150, 300, 200, Integer.MAX_VALUE);
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
	public void changeSelection(int row, int col, boolean toggle, boolean extend) {
    	// show the log entry for the selected row
	    LoggerEntry loggerEntry = extender.loggerList.get(row);
	    currentRow = row;
		extender.currentEntryRow = row;
	    extender.extenderPanelUI.penTesterCommentBox.setText(loggerEntry.getPenTesterComments());
	    extender.extenderPanelUI.evidenceBox.setText(loggerEntry.getEvidence());
	    extender.instancesTableModel.clearInstanceEntryList();
		extender.instancesTableModel.addAllInstanceEntry(loggerEntry.instancesList);

	    super.changeSelection(row, col, toggle, extend);
		extender.extenderPanelUI.deleteEntryButtonEnabled();
	}

	// Method to modify pentester's comments text field
	public void modifyComments(String comments) {
		extender.loggerList.get(currentRow).setPenTesterComments(comments);
	    extender.loggerTableModel.fireTableDataChanged();
	    //Checks if finding is mapped to a checklist entry
	    //If it is, set the pentesterComments variable for that checklist entry 
	    if (extender.loggerList.get(currentRow).issueNumber != null) {
	    	int issueNumber = extender.loggerList.get(currentRow).getIssueNumber();
	    	String finalComments = comments + "\n";
	    	extender.checklistLog.get(issueNumber).setPenTesterComments(finalComments);
	    }
	}

	// Method to modify pentester's evidences text field
	public void modifyEvidence(String evidences) {
		extender.loggerList.get(currentRow).setEvidence(evidences);
	    extender.loggerTableModel.fireTableDataChanged();
	    //Checks if finding is mapped to a checklist entry
	    //If it is, set the evidence variable for that checklist entry
	    if (extender.loggerList.get(currentRow).issueNumber != null) {
		    int issueNumber = extender.loggerList.get(currentRow).getIssueNumber();
		    String finalEvidence = evidences + "\n";
		    extender.checklistLog.get(issueNumber).setEvidence(finalEvidence);
	    }
	}

	// Method to setup WTSG mapping column with dropdown combo
	public void setUpIssueColumn(TableColumn column) {
        column.setCellEditor(new DefaultCellEditor(extender.comboBox));
    }

	// Method to setup WTSG mapping column with dropdown combo
	public void generateWSTGList() {
    	JComboBox<String> comboBox = extender.comboBox;
    	// Add an N.A. to mark finding as false positive
		comboBox.addItem("N.A.");
		for (ChecklistEntry entry : extender.checklistLog) {
        	String comboEntry = entry.getRefNumber() + " - " + entry.getTestName();
			comboBox.addItem(comboEntry);
        }
	}

	// Method to reset WTSG mapping column
	public void resetList() {
		extender.comboBox.removeAllItems();
		JComboBox<String> comboBox = extender.comboBox;
		// Add an N.A. to mark finding as false positive
		comboBox.addItem("N.A.");
		for (ChecklistEntry entry : extender.checklistLog) {
			if (!entry.isExcluded()){
				String comboEntry = entry.getRefNumber() + " - " + entry.getTestName();
				comboBox.addItem(comboEntry);
			}
		}
	}

	// Method to delete logger entry
	public void deleteEntry() {
		extender.extenderPanelUI.deleteEntryButton.setEnabled(false);
		extender.loggerList.remove(currentRow);
		// update UI
		// Inform user about entry deletion
		extender.extenderPanelUI.scanStatusLabel.setText("Entry deleted");
		extender.callbacks.issueAlert("Entry deleted");
		// Repaint logger entries table
		extender.loggerTableModel.updateLoggerEntryTable();
	}
}
