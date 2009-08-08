// WATCHER
//
// WatcherConfig.Designer.cs
// Main implementation of WatcherConfig UI.
//
// Copyright (c) 2009 Casaba Security, LLC
// All Rights Reserved.
//

namespace CasabaSecurity.Web.Watcher
{
    partial class WatcherConfigControl
    {
        /// <summary> 
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary> 
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Component Designer generated code

        /// <summary> 
        /// Required method for Designer support - do not modify 
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(WatcherConfigControl));
            this.configGroupBox = new System.Windows.Forms.GroupBox();
            this.regexlabel = new System.Windows.Forms.Label();
            this.ClearDomainButton = new System.Windows.Forms.Button();
            this.label3 = new System.Windows.Forms.Label();
            this.trustedDomainListBox = new System.Windows.Forms.ListView();
            this.AddTrustedDomainButton = new System.Windows.Forms.Button();
            this.label2 = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.trustedDomainTextBox = new System.Windows.Forms.TextBox();
            this.originDomainTextBox = new System.Windows.Forms.TextBox();
            this.enablegroupBox = new System.Windows.Forms.GroupBox();
            this.casabapictureBox = new System.Windows.Forms.PictureBox();
            this.saveconfigbutton = new System.Windows.Forms.Button();
            this.CheckLatestButton = new System.Windows.Forms.Button();
            this.linkLabel = new System.Windows.Forms.LinkLabel();
            this.enableCheckBox = new System.Windows.Forms.CheckBox();
            this.checklistgroupBox = new System.Windows.Forms.GroupBox();
            this.checklistsplitContainer = new System.Windows.Forms.SplitContainer();
            this.enabledChecksListView = new System.Windows.Forms.ListView();
            this.columnHeader1 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader2 = new System.Windows.Forms.ColumnHeader();
            this.labelDisableAll = new System.Windows.Forms.LinkLabel();
            this.FilterBox = new System.Windows.Forms.Label();
            this.domainconfigButton = new System.Windows.Forms.Button();
            this.labelEnableAll = new System.Windows.Forms.LinkLabel();
            this.filtertextBox = new System.Windows.Forms.TextBox();
            this.configGroupBox.SuspendLayout();
            this.enablegroupBox.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.casabapictureBox)).BeginInit();
            this.checklistgroupBox.SuspendLayout();
            this.checklistsplitContainer.Panel1.SuspendLayout();
            this.checklistsplitContainer.SuspendLayout();
            this.SuspendLayout();
            // 
            // configGroupBox
            // 
            this.configGroupBox.Controls.Add(this.regexlabel);
            this.configGroupBox.Controls.Add(this.ClearDomainButton);
            this.configGroupBox.Controls.Add(this.label3);
            this.configGroupBox.Controls.Add(this.trustedDomainListBox);
            this.configGroupBox.Controls.Add(this.AddTrustedDomainButton);
            this.configGroupBox.Controls.Add(this.label2);
            this.configGroupBox.Controls.Add(this.label1);
            this.configGroupBox.Controls.Add(this.trustedDomainTextBox);
            this.configGroupBox.Controls.Add(this.originDomainTextBox);
            this.configGroupBox.Dock = System.Windows.Forms.DockStyle.Top;
            this.configGroupBox.Location = new System.Drawing.Point(0, 72);
            this.configGroupBox.Name = "configGroupBox";
            this.configGroupBox.Size = new System.Drawing.Size(767, 183);
            this.configGroupBox.TabIndex = 2;
            this.configGroupBox.TabStop = false;
            this.configGroupBox.Text = "Domain(s)";
            // 
            // regexlabel
            // 
            this.regexlabel.AutoSize = true;
            this.regexlabel.Location = new System.Drawing.Point(22, 154);
            this.regexlabel.Name = "regexlabel";
            this.regexlabel.Size = new System.Drawing.Size(256, 13);
            this.regexlabel.TabIndex = 8;
            this.regexlabel.Text = "Note: Both Domain fields accept regular expressions.";
            // 
            // ClearDomainButton
            // 
            this.ClearDomainButton.Location = new System.Drawing.Point(410, 119);
            this.ClearDomainButton.Name = "ClearDomainButton";
            this.ClearDomainButton.Size = new System.Drawing.Size(75, 23);
            this.ClearDomainButton.TabIndex = 7;
            this.ClearDomainButton.Text = "Delete";
            this.ClearDomainButton.UseVisualStyleBackColor = true;
            this.ClearDomainButton.Click += new System.EventHandler(this.ClearDomainButton_Click);
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(225, 24);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(96, 13);
            this.label3.TabIndex = 5;
            this.label3.Text = "Trusted Domain(s):";
            // 
            // trustedDomainListBox
            // 
            this.trustedDomainListBox.Location = new System.Drawing.Point(228, 42);
            this.trustedDomainListBox.Name = "trustedDomainListBox";
            this.trustedDomainListBox.Size = new System.Drawing.Size(257, 71);
            this.trustedDomainListBox.TabIndex = 6;
            this.trustedDomainListBox.UseCompatibleStateImageBehavior = false;
            this.trustedDomainListBox.View = System.Windows.Forms.View.List;
            // 
            // AddTrustedDomainButton
            // 
            this.AddTrustedDomainButton.Location = new System.Drawing.Point(125, 119);
            this.AddTrustedDomainButton.Name = "AddTrustedDomainButton";
            this.AddTrustedDomainButton.Size = new System.Drawing.Size(75, 23);
            this.AddTrustedDomainButton.TabIndex = 4;
            this.AddTrustedDomainButton.Text = "Add";
            this.AddTrustedDomainButton.UseVisualStyleBackColor = true;
            this.AddTrustedDomainButton.Click += new System.EventHandler(this.AddTrustedDomainButton_Click);
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(22, 75);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(85, 13);
            this.label2.TabIndex = 2;
            this.label2.Text = "Trusted Domain:";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(22, 24);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(76, 13);
            this.label1.TabIndex = 0;
            this.label1.Text = "Origin Domain:";
            // 
            // trustedDomainTextBox
            // 
            this.trustedDomainTextBox.Location = new System.Drawing.Point(25, 93);
            this.trustedDomainTextBox.Name = "trustedDomainTextBox";
            this.trustedDomainTextBox.Size = new System.Drawing.Size(175, 20);
            this.trustedDomainTextBox.TabIndex = 3;
            // 
            // originDomainTextBox
            // 
            this.originDomainTextBox.Location = new System.Drawing.Point(25, 42);
            this.originDomainTextBox.Name = "originDomainTextBox";
            this.originDomainTextBox.Size = new System.Drawing.Size(175, 20);
            this.originDomainTextBox.TabIndex = 1;
            this.originDomainTextBox.TextChanged += new System.EventHandler(this.originDomainTextBox_TextChanged);
            // 
            // enablegroupBox
            // 
            this.enablegroupBox.Controls.Add(this.casabapictureBox);
            this.enablegroupBox.Controls.Add(this.saveconfigbutton);
            this.enablegroupBox.Controls.Add(this.CheckLatestButton);
            this.enablegroupBox.Controls.Add(this.linkLabel);
            this.enablegroupBox.Controls.Add(this.enableCheckBox);
            this.enablegroupBox.Dock = System.Windows.Forms.DockStyle.Top;
            this.enablegroupBox.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.enablegroupBox.Location = new System.Drawing.Point(0, 0);
            this.enablegroupBox.Name = "enablegroupBox";
            this.enablegroupBox.Size = new System.Drawing.Size(767, 72);
            this.enablegroupBox.TabIndex = 1;
            this.enablegroupBox.TabStop = false;
            this.enablegroupBox.Text = "Watcher by   ";
            // 
            // casabapictureBox
            // 
            this.casabapictureBox.Dock = System.Windows.Forms.DockStyle.Left;
            this.casabapictureBox.Image = ((System.Drawing.Image)(resources.GetObject("casabapictureBox.Image")));
            this.casabapictureBox.Location = new System.Drawing.Point(3, 16);
            this.casabapictureBox.Margin = new System.Windows.Forms.Padding(3, 3, 100, 100);
            this.casabapictureBox.Name = "casabapictureBox";
            this.casabapictureBox.Size = new System.Drawing.Size(64, 53);
            this.casabapictureBox.SizeMode = System.Windows.Forms.PictureBoxSizeMode.CenterImage;
            this.casabapictureBox.TabIndex = 5;
            this.casabapictureBox.TabStop = false;
            this.casabapictureBox.Visible = false;
            // 
            // saveconfigbutton
            // 
            this.saveconfigbutton.AutoSize = true;
            this.saveconfigbutton.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.saveconfigbutton.Location = new System.Drawing.Point(211, 30);
            this.saveconfigbutton.Name = "saveconfigbutton";
            this.saveconfigbutton.Size = new System.Drawing.Size(107, 23);
            this.saveconfigbutton.TabIndex = 2;
            this.saveconfigbutton.Text = "Save Configuration";
            this.saveconfigbutton.UseVisualStyleBackColor = true;
            this.saveconfigbutton.Click += new System.EventHandler(this.saveconfigbutton_Click);
            // 
            // CheckLatestButton
            // 
            this.CheckLatestButton.AutoSize = true;
            this.CheckLatestButton.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.CheckLatestButton.Location = new System.Drawing.Point(347, 30);
            this.CheckLatestButton.Name = "CheckLatestButton";
            this.CheckLatestButton.Size = new System.Drawing.Size(138, 23);
            this.CheckLatestButton.TabIndex = 3;
            this.CheckLatestButton.Text = "Check Latest Version";
            this.CheckLatestButton.UseVisualStyleBackColor = true;
            this.CheckLatestButton.Click += new System.EventHandler(this.CheckLatestButton_Click_1);
            // 
            // linkLabel
            // 
            this.linkLabel.AutoSize = true;
            this.linkLabel.Location = new System.Drawing.Point(77, 0);
            this.linkLabel.Margin = new System.Windows.Forms.Padding(6, 0, 6, 0);
            this.linkLabel.Name = "linkLabel";
            this.linkLabel.Size = new System.Drawing.Size(99, 13);
            this.linkLabel.TabIndex = 0;
            this.linkLabel.TabStop = true;
            this.linkLabel.Text = "Casaba Security";
            this.linkLabel.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.linkLabel_LinkClicked);
            // 
            // enableCheckBox
            // 
            this.enableCheckBox.AutoSize = true;
            this.enableCheckBox.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.enableCheckBox.Location = new System.Drawing.Point(110, 34);
            this.enableCheckBox.Name = "enableCheckBox";
            this.enableCheckBox.Size = new System.Drawing.Size(59, 17);
            this.enableCheckBox.TabIndex = 1;
            this.enableCheckBox.Text = "Enable";
            this.enableCheckBox.UseVisualStyleBackColor = true;
            this.enableCheckBox.CheckedChanged += new System.EventHandler(this.enableCheckBox_CheckedChanged);
            // 
            // checklistgroupBox
            // 
            this.checklistgroupBox.AutoSize = true;
            this.checklistgroupBox.Controls.Add(this.checklistsplitContainer);
            this.checklistgroupBox.Controls.Add(this.labelDisableAll);
            this.checklistgroupBox.Controls.Add(this.FilterBox);
            this.checklistgroupBox.Controls.Add(this.domainconfigButton);
            this.checklistgroupBox.Controls.Add(this.labelEnableAll);
            this.checklistgroupBox.Controls.Add(this.filtertextBox);
            this.checklistgroupBox.Dock = System.Windows.Forms.DockStyle.Fill;
            this.checklistgroupBox.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.checklistgroupBox.Location = new System.Drawing.Point(0, 255);
            this.checklistgroupBox.Name = "checklistgroupBox";
            this.checklistgroupBox.Padding = new System.Windows.Forms.Padding(0);
            this.checklistgroupBox.Size = new System.Drawing.Size(767, 354);
            this.checklistgroupBox.TabIndex = 0;
            this.checklistgroupBox.TabStop = false;
            this.checklistgroupBox.Text = "Check(s)";
            // 
            // checklistsplitContainer
            // 
            this.checklistsplitContainer.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom)
                        | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.checklistsplitContainer.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.checklistsplitContainer.Location = new System.Drawing.Point(6, 45);
            this.checklistsplitContainer.Name = "checklistsplitContainer";
            this.checklistsplitContainer.Orientation = System.Windows.Forms.Orientation.Horizontal;
            // 
            // checklistsplitContainer.Panel1
            // 
            this.checklistsplitContainer.Panel1.AutoScroll = true;
            this.checklistsplitContainer.Panel1.Controls.Add(this.enabledChecksListView);
            // 
            // checklistsplitContainer.Panel2
            // 
            this.checklistsplitContainer.Panel2.BackColor = System.Drawing.Color.Transparent;
            this.checklistsplitContainer.Size = new System.Drawing.Size(755, 306);
            this.checklistsplitContainer.SplitterDistance = 134;
            this.checklistsplitContainer.TabIndex = 6;
            // 
            // enabledChecksListView
            // 
            this.enabledChecksListView.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.enabledChecksListView.CheckBoxes = true;
            this.enabledChecksListView.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.columnHeader1,
            this.columnHeader2});
            this.enabledChecksListView.Dock = System.Windows.Forms.DockStyle.Fill;
            this.enabledChecksListView.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.enabledChecksListView.FullRowSelect = true;
            this.enabledChecksListView.GridLines = true;
            this.enabledChecksListView.HeaderStyle = System.Windows.Forms.ColumnHeaderStyle.Nonclickable;
            this.enabledChecksListView.Location = new System.Drawing.Point(0, 0);
            this.enabledChecksListView.Margin = new System.Windows.Forms.Padding(3, 0, 3, 0);
            this.enabledChecksListView.MultiSelect = false;
            this.enabledChecksListView.Name = "enabledChecksListView";
            this.enabledChecksListView.Size = new System.Drawing.Size(753, 132);
            this.enabledChecksListView.Sorting = System.Windows.Forms.SortOrder.Ascending;
            this.enabledChecksListView.TabIndex = 0;
            this.enabledChecksListView.UseCompatibleStateImageBehavior = false;
            this.enabledChecksListView.View = System.Windows.Forms.View.Details;
            this.enabledChecksListView.SelectedIndexChanged += new System.EventHandler(this.enabledChecksListView_SelectedIndexChanged);
            // 
            // columnHeader1
            // 
            this.columnHeader1.Text = "Description";
            this.columnHeader1.Width = 150;
            // 
            // columnHeader2
            // 
            this.columnHeader2.Text = "Standards Compliance";
            this.columnHeader2.Width = 150;
            // 
            // labelDisableAll
            // 
            this.labelDisableAll.AutoSize = true;
            this.labelDisableAll.Location = new System.Drawing.Point(78, 19);
            this.labelDisableAll.Name = "labelDisableAll";
            this.labelDisableAll.Size = new System.Drawing.Size(64, 13);
            this.labelDisableAll.TabIndex = 1;
            this.labelDisableAll.TabStop = true;
            this.labelDisableAll.Text = "Disable all...";
            this.labelDisableAll.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.labelDisableAll_LinkClicked);
            // 
            // FilterBox
            // 
            this.FilterBox.AutoSize = true;
            this.FilterBox.Location = new System.Drawing.Point(148, 19);
            this.FilterBox.Name = "FilterBox";
            this.FilterBox.Size = new System.Drawing.Size(44, 13);
            this.FilterBox.TabIndex = 2;
            this.FilterBox.Text = "Search:";
            // 
            // domainconfigButton
            // 
            this.domainconfigButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.domainconfigButton.AutoSize = true;
            this.domainconfigButton.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            this.domainconfigButton.Location = new System.Drawing.Point(637, 16);
            this.domainconfigButton.Name = "domainconfigButton";
            this.domainconfigButton.Size = new System.Drawing.Size(124, 23);
            this.domainconfigButton.TabIndex = 4;
            this.domainconfigButton.Text = "Restore Previous View";
            this.domainconfigButton.UseVisualStyleBackColor = true;
            this.domainconfigButton.Visible = false;
            this.domainconfigButton.Click += new System.EventHandler(this.domainconfigButton_Click);
            // 
            // labelEnableAll
            // 
            this.labelEnableAll.AutoSize = true;
            this.labelEnableAll.Location = new System.Drawing.Point(10, 19);
            this.labelEnableAll.Name = "labelEnableAll";
            this.labelEnableAll.Size = new System.Drawing.Size(62, 13);
            this.labelEnableAll.TabIndex = 0;
            this.labelEnableAll.TabStop = true;
            this.labelEnableAll.Text = "Enable all...";
            this.labelEnableAll.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.labelEnableAll_LinkClicked);
            // 
            // filtertextBox
            // 
            this.filtertextBox.Location = new System.Drawing.Point(198, 16);
            this.filtertextBox.Name = "filtertextBox";
            this.filtertextBox.Size = new System.Drawing.Size(107, 20);
            this.filtertextBox.TabIndex = 3;
            this.filtertextBox.TextChanged += new System.EventHandler(this.filtertextBox_TextChanged);
            // 
            // WatcherConfigControl
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.AutoScroll = true;
            this.Controls.Add(this.checklistgroupBox);
            this.Controls.Add(this.configGroupBox);
            this.Controls.Add(this.enablegroupBox);
            this.Name = "WatcherConfigControl";
            this.Size = new System.Drawing.Size(767, 609);
            this.configGroupBox.ResumeLayout(false);
            this.configGroupBox.PerformLayout();
            this.enablegroupBox.ResumeLayout(false);
            this.enablegroupBox.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.casabapictureBox)).EndInit();
            this.checklistgroupBox.ResumeLayout(false);
            this.checklistgroupBox.PerformLayout();
            this.checklistsplitContainer.Panel1.ResumeLayout(false);
            this.checklistsplitContainer.ResumeLayout(false);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        public System.Windows.Forms.GroupBox configGroupBox;
        public System.Windows.Forms.Button ClearDomainButton;
        public System.Windows.Forms.Label label3;
        public System.Windows.Forms.ListView trustedDomainListBox;
        public System.Windows.Forms.Button AddTrustedDomainButton;
        public System.Windows.Forms.Label label2;
        public System.Windows.Forms.Label label1;
        public System.Windows.Forms.TextBox trustedDomainTextBox;
        public System.Windows.Forms.TextBox originDomainTextBox;
        private System.Windows.Forms.Label regexlabel;
        public System.Windows.Forms.GroupBox enablegroupBox;
        private System.Windows.Forms.Button saveconfigbutton;
        public System.Windows.Forms.Button CheckLatestButton;
        public System.Windows.Forms.LinkLabel linkLabel;
        public System.Windows.Forms.CheckBox enableCheckBox;
        private System.Windows.Forms.GroupBox checklistgroupBox;
        private System.Windows.Forms.SplitContainer checklistsplitContainer;
        private System.Windows.Forms.PictureBox casabapictureBox;
        private System.Windows.Forms.LinkLabel labelDisableAll;
        public System.Windows.Forms.ListView enabledChecksListView;
        private System.Windows.Forms.ColumnHeader columnHeader1;
        private System.Windows.Forms.ColumnHeader columnHeader2;
        private System.Windows.Forms.Label FilterBox;
        private System.Windows.Forms.Button domainconfigButton;
        private System.Windows.Forms.LinkLabel labelEnableAll;
        private System.Windows.Forms.TextBox filtertextBox;
    }
}