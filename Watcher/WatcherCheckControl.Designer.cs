namespace CasabaSecurity.Web.Watcher
{
    partial class WatcherCheckControl
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
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(WatcherCheckControl));
            this.checklistsplitContainer = new System.Windows.Forms.SplitContainer();
            this.enabledChecksListView = new System.Windows.Forms.ListView();
            this.columnHeader1 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeader2 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.referencepanel = new System.Windows.Forms.Panel();
            this.reflinkLabel = new System.Windows.Forms.LinkLabel();
            this.referencelabel = new System.Windows.Forms.Label();
            this.labelDisableAll = new System.Windows.Forms.LinkLabel();
            this.FilterBox = new System.Windows.Forms.Label();
            this.domainconfigButton = new System.Windows.Forms.Button();
            this.labelEnableAll = new System.Windows.Forms.LinkLabel();
            this.filtertextBox = new System.Windows.Forms.TextBox();
            this.label2 = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.selectionpanel = new System.Windows.Forms.Panel();
            this.toolTipCheckControl = new System.Windows.Forms.ToolTip(this.components);
            this.pnlCopyright = new System.Windows.Forms.Panel();
            this.rightslabel = new System.Windows.Forms.Label();
            this.linkLabel1 = new System.Windows.Forms.LinkLabel();
            this.pbCasaba = new System.Windows.Forms.PictureBox();
            this.copyrightlabel = new System.Windows.Forms.Label();
            this.checklistsplitContainer.Panel1.SuspendLayout();
            this.checklistsplitContainer.Panel2.SuspendLayout();
            this.checklistsplitContainer.SuspendLayout();
            this.referencepanel.SuspendLayout();
            this.selectionpanel.SuspendLayout();
            this.pnlCopyright.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.pbCasaba)).BeginInit();
            this.SuspendLayout();
            // 
            // checklistsplitContainer
            // 
            this.checklistsplitContainer.BackColor = System.Drawing.Color.Transparent;
            this.checklistsplitContainer.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.checklistsplitContainer.Dock = System.Windows.Forms.DockStyle.Fill;
            this.checklistsplitContainer.Location = new System.Drawing.Point(0, 40);
            this.checklistsplitContainer.Name = "checklistsplitContainer";
            this.checklistsplitContainer.Orientation = System.Windows.Forms.Orientation.Horizontal;
            // 
            // checklistsplitContainer.Panel1
            // 
            this.checklistsplitContainer.Panel1.Controls.Add(this.enabledChecksListView);
            // 
            // checklistsplitContainer.Panel2
            // 
            this.checklistsplitContainer.Panel2.AutoScroll = true;
            this.checklistsplitContainer.Panel2.BackColor = System.Drawing.Color.Transparent;
            this.checklistsplitContainer.Panel2.BackgroundImageLayout = System.Windows.Forms.ImageLayout.None;
            this.checklistsplitContainer.Panel2.Controls.Add(this.referencepanel);
            this.checklistsplitContainer.Size = new System.Drawing.Size(600, 524);
            this.checklistsplitContainer.SplitterDistance = 234;
            this.checklistsplitContainer.TabIndex = 4;
            // 
            // enabledChecksListView
            // 
            this.enabledChecksListView.BackColor = System.Drawing.SystemColors.Window;
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
            this.enabledChecksListView.Margin = new System.Windows.Forms.Padding(0);
            this.enabledChecksListView.MultiSelect = false;
            this.enabledChecksListView.Name = "enabledChecksListView";
            this.enabledChecksListView.Size = new System.Drawing.Size(598, 232);
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
            // referencepanel
            // 
            this.referencepanel.BackColor = System.Drawing.Color.LightGray;
            this.referencepanel.Controls.Add(this.reflinkLabel);
            this.referencepanel.Controls.Add(this.referencelabel);
            this.referencepanel.Dock = System.Windows.Forms.DockStyle.Top;
            this.referencepanel.Location = new System.Drawing.Point(0, 0);
            this.referencepanel.Name = "referencepanel";
            this.referencepanel.Size = new System.Drawing.Size(598, 34);
            this.referencepanel.TabIndex = 0;
            this.referencepanel.Paint += new System.Windows.Forms.PaintEventHandler(this.referencepanel_Paint);
            // 
            // reflinkLabel
            // 
            this.reflinkLabel.AutoSize = true;
            // Position the check's reference link over past the "Reference: " introduction
            this.reflinkLabel.Location = new System.Drawing.Point(71, 9);
            this.reflinkLabel.Name = "reflinkLabel";
            this.reflinkLabel.Size = new System.Drawing.Size(0, 13);
            this.reflinkLabel.TabIndex = 1;
            this.reflinkLabel.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.reflinkLabel_LinkClicked);
            // 
            // referencelabel
            // 
            this.referencelabel.AutoSize = true;
            this.referencelabel.Location = new System.Drawing.Point(3, 9);
            this.referencelabel.Name = "referencelabel";
            this.referencelabel.Size = new System.Drawing.Size(141, 13);
            this.referencelabel.TabIndex = 0;
            this.referencelabel.Text = "Reference: ";
            // 
            // labelDisableAll
            // 
            this.labelDisableAll.AutoSize = true;
            this.labelDisableAll.Location = new System.Drawing.Point(71, 13);
            this.labelDisableAll.Name = "labelDisableAll";
            this.labelDisableAll.Size = new System.Drawing.Size(64, 13);
            this.labelDisableAll.TabIndex = 1;
            this.labelDisableAll.TabStop = true;
            this.labelDisableAll.Text = "Disable all...";
            this.toolTipCheckControl.SetToolTip(this.labelDisableAll, "Disable all checks and disable Watcher");
            this.labelDisableAll.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.labelDisableAll_LinkClicked);
            // 
            // FilterBox
            // 
            this.FilterBox.AutoSize = true;
            this.FilterBox.Location = new System.Drawing.Point(165, 13);
            this.FilterBox.Name = "FilterBox";
            this.FilterBox.Size = new System.Drawing.Size(44, 13);
            this.FilterBox.TabIndex = 2;
            this.FilterBox.Text = "Search:";
            this.toolTipCheckControl.SetToolTip(this.FilterBox, "Enter text to filter check descriptions with.");
            // 
            // domainconfigButton
            // 
            this.domainconfigButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.domainconfigButton.AutoSize = true;
            this.domainconfigButton.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            this.domainconfigButton.Location = new System.Drawing.Point(1032, 13);
            this.domainconfigButton.Name = "domainconfigButton";
            this.domainconfigButton.Size = new System.Drawing.Size(132, 23);
            this.domainconfigButton.TabIndex = 4;
            this.domainconfigButton.Text = "Restore Full Config View";
            this.domainconfigButton.UseVisualStyleBackColor = true;
            this.domainconfigButton.Visible = false;
            this.domainconfigButton.Click += new System.EventHandler(this.domainconfigButton_Click);
            // 
            // labelEnableAll
            // 
            this.labelEnableAll.AutoSize = true;
            this.labelEnableAll.Location = new System.Drawing.Point(3, 13);
            this.labelEnableAll.Name = "labelEnableAll";
            this.labelEnableAll.Size = new System.Drawing.Size(62, 13);
            this.labelEnableAll.TabIndex = 0;
            this.labelEnableAll.TabStop = true;
            this.labelEnableAll.Text = "Enable all...";
            this.toolTipCheckControl.SetToolTip(this.labelEnableAll, "Enable all checks");
            this.labelEnableAll.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.labelEnableAll_LinkClicked);
            // 
            // filtertextBox
            // 
            this.filtertextBox.Location = new System.Drawing.Point(213, 10);
            this.filtertextBox.Name = "filtertextBox";
            this.filtertextBox.Size = new System.Drawing.Size(278, 20);
            this.filtertextBox.TabIndex = 3;
            this.toolTipCheckControl.SetToolTip(this.filtertextBox, "Enter text to filter check descriptions with.");
            this.filtertextBox.TextChanged += new System.EventHandler(this.filtertextBox_TextChanged);
            // 
            // label2
            // 
            this.label2.Location = new System.Drawing.Point(0, 0);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(100, 23);
            this.label2.TabIndex = 0;
            // 
            // label1
            // 
            this.label1.BackColor = System.Drawing.Color.Transparent;
            this.label1.Location = new System.Drawing.Point(0, 0);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(100, 23);
            this.label1.TabIndex = 0;
            // 
            // selectionpanel
            // 
            this.selectionpanel.BackColor = System.Drawing.Color.Transparent;
            this.selectionpanel.Controls.Add(this.labelEnableAll);
            this.selectionpanel.Controls.Add(this.filtertextBox);
            this.selectionpanel.Controls.Add(this.labelDisableAll);
            this.selectionpanel.Controls.Add(this.FilterBox);
            this.selectionpanel.Dock = System.Windows.Forms.DockStyle.Top;
            this.selectionpanel.Location = new System.Drawing.Point(0, 0);
            this.selectionpanel.Name = "selectionpanel";
            this.selectionpanel.Size = new System.Drawing.Size(600, 40);
            this.selectionpanel.TabIndex = 5;
            // 
            // pnlCopyright
            // 
            this.pnlCopyright.BackColor = System.Drawing.Color.Transparent;
            this.pnlCopyright.Controls.Add(this.rightslabel);
            this.pnlCopyright.Controls.Add(this.linkLabel1);
            this.pnlCopyright.Controls.Add(this.pbCasaba);
            this.pnlCopyright.Controls.Add(this.copyrightlabel);
            this.pnlCopyright.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.pnlCopyright.Location = new System.Drawing.Point(0, 564);
            this.pnlCopyright.Margin = new System.Windows.Forms.Padding(0);
            this.pnlCopyright.Name = "pnlCopyright";
            this.pnlCopyright.Size = new System.Drawing.Size(600, 55);
            this.pnlCopyright.TabIndex = 6;
            // 
            // rightslabel
            // 
            this.rightslabel.AutoSize = true;
            this.rightslabel.Location = new System.Drawing.Point(500, 20);
            this.rightslabel.Name = "rightslabel";
            this.rightslabel.Size = new System.Drawing.Size(93, 13);
            this.rightslabel.TabIndex = 6;
            this.rightslabel.Text = "All rights reserved.";
            // 
            // linkLabel1
            // 
            this.linkLabel1.AutoSize = true;
            this.linkLabel1.BackColor = System.Drawing.Color.Transparent;
            this.linkLabel1.Location = new System.Drawing.Point(385, 20);
            this.linkLabel1.Margin = new System.Windows.Forms.Padding(6, 0, 6, 0);
            this.linkLabel1.Name = "linkLabel1";
            this.linkLabel1.Size = new System.Drawing.Size(112, 13);
            this.linkLabel1.TabIndex = 1;
            this.linkLabel1.TabStop = true;
            this.linkLabel1.Text = "Casaba Security, LLC.";
            // 
            // pbCasaba
            // 
            this.pbCasaba.BackColor = System.Drawing.Color.Transparent;
            this.pbCasaba.Image = ((System.Drawing.Image)(resources.GetObject("pbCasaba.Image")));
            this.pbCasaba.Location = new System.Drawing.Point(0, 0);
            this.pbCasaba.Name = "pbCasaba";
            this.pbCasaba.Size = new System.Drawing.Size(111, 55);
            this.pbCasaba.SizeMode = System.Windows.Forms.PictureBoxSizeMode.CenterImage;
            this.pbCasaba.TabIndex = 5;
            this.pbCasaba.TabStop = false;
            // 
            // copyrightlabel
            // 
            this.copyrightlabel.AutoSize = true;
            this.copyrightlabel.Location = new System.Drawing.Point(113, 20);
            this.copyrightlabel.Name = "copyrightlabel";
            this.copyrightlabel.Size = new System.Drawing.Size(228, 13);
            this.copyrightlabel.TabIndex = 0;
            this.copyrightlabel.Text = "Watcher Web Security Tool, Copyright © 2010";
            // 
            // WatcherCheckControl
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.BackColor = System.Drawing.Color.Transparent;
            this.Controls.Add(this.checklistsplitContainer);
            this.Controls.Add(this.pnlCopyright);
            this.Controls.Add(this.selectionpanel);
            this.Controls.Add(this.domainconfigButton);
            this.Name = "WatcherCheckControl";
            this.Size = new System.Drawing.Size(600, 619);
            this.checklistsplitContainer.Panel1.ResumeLayout(false);
            this.checklistsplitContainer.Panel2.ResumeLayout(false);
            this.checklistsplitContainer.ResumeLayout(false);
            this.referencepanel.ResumeLayout(false);
            this.referencepanel.PerformLayout();
            this.selectionpanel.ResumeLayout(false);
            this.selectionpanel.PerformLayout();
            this.pnlCopyright.ResumeLayout(false);
            this.pnlCopyright.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.pbCasaba)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        public System.Windows.Forms.Label label2;
        public System.Windows.Forms.Label label1;
        public System.Windows.Forms.ListView enabledChecksListView;
        //private System.Windows.Forms.GroupBox checklistgroupBox;
        private System.Windows.Forms.SplitContainer checklistsplitContainer;
        private System.Windows.Forms.LinkLabel labelDisableAll;
        private System.Windows.Forms.ColumnHeader columnHeader1;
        private System.Windows.Forms.ColumnHeader columnHeader2;
        private System.Windows.Forms.Label FilterBox;
        private System.Windows.Forms.Button domainconfigButton;
        private System.Windows.Forms.LinkLabel labelEnableAll;
        private System.Windows.Forms.TextBox filtertextBox;
        private System.Windows.Forms.Panel selectionpanel;
        private System.Windows.Forms.ToolTip toolTipCheckControl;
        private System.Windows.Forms.Panel pnlCopyright;
        private System.Windows.Forms.Label rightslabel;
        public System.Windows.Forms.LinkLabel linkLabel1;
        private System.Windows.Forms.PictureBox pbCasaba;
        private System.Windows.Forms.Label copyrightlabel;
        private System.Windows.Forms.Panel referencepanel;
        private System.Windows.Forms.Label referencelabel;
        private System.Windows.Forms.LinkLabel reflinkLabel;
    }
}
