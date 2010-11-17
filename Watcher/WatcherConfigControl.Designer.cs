// WATCHER
//
// WatcherConfig.Designer.cs
// Main implementation of WatcherConfig UI.
//
// Copyright (c) 2010 Casaba Security, LLC
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
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(WatcherConfigControl));
            this.configGroupBox = new System.Windows.Forms.GroupBox();
            this.lblDomainsAcceptRegularExpressions = new System.Windows.Forms.Label();
            this.ClearDomainButton = new System.Windows.Forms.Button();
            this.label3 = new System.Windows.Forms.Label();
            this.trustedDomainListBox = new System.Windows.Forms.ListView();
            this.AddTrustedDomainButton = new System.Windows.Forms.Button();
            this.label2 = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.trustedDomainTextBox = new System.Windows.Forms.TextBox();
            this.originDomainTextBox = new System.Windows.Forms.TextBox();
            this.enableCheckBox = new System.Windows.Forms.CheckBox();
            this.CheckLatestButton = new System.Windows.Forms.Button();
            this.saveconfigbutton = new System.Windows.Forms.Button();
            this.appgroupBox = new System.Windows.Forms.GroupBox();
            this.autovercheckBox = new System.Windows.Forms.CheckBox();
            this.autosavecheckBox = new System.Windows.Forms.CheckBox();
            this.toolTipConfigControl = new System.Windows.Forms.ToolTip(this.components);
            this.watcherbackgroundbutton = new System.Windows.Forms.Button();
            this.ProcessOffline = new System.Windows.Forms.Button();
            this.pnlCopyright = new System.Windows.Forms.Panel();
            this.rightslabel = new System.Windows.Forms.Label();
            this.linkLabel1 = new System.Windows.Forms.LinkLabel();
            this.pbCasaba = new System.Windows.Forms.PictureBox();
            this.copyrightlabel = new System.Windows.Forms.Label();
            this.uigroupBox = new System.Windows.Forms.GroupBox();
            this.colorDialog = new System.Windows.Forms.ColorDialog();
            this.pluginPanel = new System.Windows.Forms.Panel();
            this.configGroupBox.SuspendLayout();
            this.appgroupBox.SuspendLayout();
            this.pnlCopyright.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.pbCasaba)).BeginInit();
            this.uigroupBox.SuspendLayout();
            this.SuspendLayout();
            // 
            // configGroupBox
            // 
            this.configGroupBox.Controls.Add(this.lblDomainsAcceptRegularExpressions);
            this.configGroupBox.Controls.Add(this.ClearDomainButton);
            this.configGroupBox.Controls.Add(this.label3);
            this.configGroupBox.Controls.Add(this.trustedDomainListBox);
            this.configGroupBox.Controls.Add(this.AddTrustedDomainButton);
            this.configGroupBox.Controls.Add(this.label2);
            this.configGroupBox.Controls.Add(this.label1);
            this.configGroupBox.Controls.Add(this.trustedDomainTextBox);
            this.configGroupBox.Controls.Add(this.originDomainTextBox);
            this.configGroupBox.Location = new System.Drawing.Point(3, 136);
            this.configGroupBox.Name = "configGroupBox";
            this.configGroupBox.Size = new System.Drawing.Size(479, 183);
            this.configGroupBox.TabIndex = 3;
            this.configGroupBox.TabStop = false;
            this.configGroupBox.Text = "Domains";
            this.toolTipConfigControl.SetToolTip(this.configGroupBox, "Load a .SAZ file and then click to process those sessions offline.");
            // 
            // lblDomainsAcceptRegularExpressions
            // 
            this.lblDomainsAcceptRegularExpressions.AutoSize = true;
            this.lblDomainsAcceptRegularExpressions.Location = new System.Drawing.Point(6, 156);
            this.lblDomainsAcceptRegularExpressions.Name = "lblDomainsAcceptRegularExpressions";
            this.lblDomainsAcceptRegularExpressions.Size = new System.Drawing.Size(254, 13);
            this.lblDomainsAcceptRegularExpressions.TabIndex = 8;
            this.lblDomainsAcceptRegularExpressions.Text = "Note: Both domain fields accept regular expressions.";
            // 
            // ClearDomainButton
            // 
            this.ClearDomainButton.Location = new System.Drawing.Point(394, 121);
            this.ClearDomainButton.Name = "ClearDomainButton";
            this.ClearDomainButton.Size = new System.Drawing.Size(75, 23);
            this.ClearDomainButton.TabIndex = 7;
            this.ClearDomainButton.Text = "Remove";
            this.ClearDomainButton.UseVisualStyleBackColor = true;
            this.ClearDomainButton.Click += new System.EventHandler(this.ClearDomainButton_Click);
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(209, 26);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(88, 13);
            this.label3.TabIndex = 5;
            this.label3.Text = "Trusted domains:";
            this.toolTipConfigControl.SetToolTip(this.label3, "Domains listed are exempt from cross-domain checks.");
            // 
            // trustedDomainListBox
            // 
            this.trustedDomainListBox.Location = new System.Drawing.Point(212, 44);
            this.trustedDomainListBox.Name = "trustedDomainListBox";
            this.trustedDomainListBox.Size = new System.Drawing.Size(257, 71);
            this.trustedDomainListBox.TabIndex = 6;
            this.toolTipConfigControl.SetToolTip(this.trustedDomainListBox, "Domains listed are exempt from cross-domain checks.");
            this.trustedDomainListBox.UseCompatibleStateImageBehavior = false;
            this.trustedDomainListBox.View = System.Windows.Forms.View.List;
            // 
            // AddTrustedDomainButton
            // 
            this.AddTrustedDomainButton.Location = new System.Drawing.Point(109, 121);
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
            this.label2.Location = new System.Drawing.Point(6, 77);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(83, 13);
            this.label2.TabIndex = 2;
            this.label2.Text = "Trusted domain:";
            this.toolTipConfigControl.SetToolTip(this.label2, "Domains listed are exempt from cross-domain checks.");
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(6, 26);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(74, 13);
            this.label1.TabIndex = 0;
            this.label1.Text = "Origin domain:";
            this.toolTipConfigControl.SetToolTip(this.label1, "Traffic from this domain is watched. Defaults to all. Cross-domain checks examine" +
                    " interaction between external sites and the specified domain.");
            // 
            // trustedDomainTextBox
            // 
            this.trustedDomainTextBox.Location = new System.Drawing.Point(9, 95);
            this.trustedDomainTextBox.Name = "trustedDomainTextBox";
            this.trustedDomainTextBox.Size = new System.Drawing.Size(175, 20);
            this.trustedDomainTextBox.TabIndex = 3;
            this.toolTipConfigControl.SetToolTip(this.trustedDomainTextBox, "Domains listed are exempt from cross-domain checks.");
            // 
            // originDomainTextBox
            // 
            this.originDomainTextBox.Location = new System.Drawing.Point(9, 44);
            this.originDomainTextBox.Name = "originDomainTextBox";
            this.originDomainTextBox.Size = new System.Drawing.Size(175, 20);
            this.originDomainTextBox.TabIndex = 1;
            this.toolTipConfigControl.SetToolTip(this.originDomainTextBox, "Traffic from this domain is watched. Defaults to all. Cross-domain checks examine" +
                    " interaction between external sites and the specified domain.");
            this.originDomainTextBox.TextChanged += new System.EventHandler(this.originDomainTextBox_TextChanged);
            // 
            // enableCheckBox
            // 
            this.enableCheckBox.AutoSize = true;
            this.enableCheckBox.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.enableCheckBox.Location = new System.Drawing.Point(3, 5);
            this.enableCheckBox.Name = "enableCheckBox";
            this.enableCheckBox.Size = new System.Drawing.Size(59, 17);
            this.enableCheckBox.TabIndex = 0;
            this.enableCheckBox.Text = "Enable";
            this.toolTipConfigControl.SetToolTip(this.enableCheckBox, "Configured checks execute when this is checked.");
            this.enableCheckBox.UseVisualStyleBackColor = true;
            this.enableCheckBox.CheckedChanged += new System.EventHandler(this.enableCheckBox_CheckedChanged);
            // 
            // CheckLatestButton
            // 
            this.CheckLatestButton.AutoSize = true;
            this.CheckLatestButton.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.CheckLatestButton.Location = new System.Drawing.Point(306, 47);
            this.CheckLatestButton.Name = "CheckLatestButton";
            this.CheckLatestButton.Size = new System.Drawing.Size(138, 23);
            this.CheckLatestButton.TabIndex = 2;
            this.CheckLatestButton.Text = "Check Latest Version";
            this.toolTipConfigControl.SetToolTip(this.CheckLatestButton, "When clicked Watcher will check for newer versions of itself.");
            this.CheckLatestButton.UseVisualStyleBackColor = true;
            this.CheckLatestButton.Click += new System.EventHandler(this.CheckLatestButton_Click_1);
            // 
            // saveconfigbutton
            // 
            this.saveconfigbutton.AutoSize = true;
            this.saveconfigbutton.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.saveconfigbutton.Location = new System.Drawing.Point(306, 18);
            this.saveconfigbutton.Name = "saveconfigbutton";
            this.saveconfigbutton.Size = new System.Drawing.Size(138, 23);
            this.saveconfigbutton.TabIndex = 1;
            this.saveconfigbutton.Text = "Save Configuration";
            this.toolTipConfigControl.SetToolTip(this.saveconfigbutton, "When clicked the current Watcher configuration state is saved.");
            this.saveconfigbutton.UseVisualStyleBackColor = true;
            this.saveconfigbutton.Click += new System.EventHandler(this.saveconfigbutton_Click);
            // 
            // appgroupBox
            // 
            this.appgroupBox.Controls.Add(this.autovercheckBox);
            this.appgroupBox.Controls.Add(this.autosavecheckBox);
            this.appgroupBox.Controls.Add(this.saveconfigbutton);
            this.appgroupBox.Controls.Add(this.CheckLatestButton);
            this.appgroupBox.Location = new System.Drawing.Point(3, 41);
            this.appgroupBox.Name = "appgroupBox";
            this.appgroupBox.Size = new System.Drawing.Size(479, 80);
            this.appgroupBox.TabIndex = 4;
            this.appgroupBox.TabStop = false;
            this.appgroupBox.Text = "Options";
            // 
            // autovercheckBox
            // 
            this.autovercheckBox.AutoSize = true;
            this.autovercheckBox.Location = new System.Drawing.Point(9, 51);
            this.autovercheckBox.Name = "autovercheckBox";
            this.autovercheckBox.Size = new System.Drawing.Size(185, 17);
            this.autovercheckBox.TabIndex = 4;
            this.autovercheckBox.Text = "Check for new version on start-up";
            this.toolTipConfigControl.SetToolTip(this.autovercheckBox, "When checked Watcher will check for a newer version every time it is started.");
            this.autovercheckBox.UseVisualStyleBackColor = true;
            this.autovercheckBox.CheckedChanged += new System.EventHandler(this.autovercheckbox_CheckedChanged);
            // 
            // autosavecheckBox
            // 
            this.autosavecheckBox.AutoSize = true;
            this.autosavecheckBox.Location = new System.Drawing.Point(9, 22);
            this.autosavecheckBox.Name = "autosavecheckBox";
            this.autosavecheckBox.Size = new System.Drawing.Size(179, 17);
            this.autosavecheckBox.TabIndex = 3;
            this.autosavecheckBox.Text = "Save configuration automatically";
            this.toolTipConfigControl.SetToolTip(this.autosavecheckBox, "When checked all configuration options are automatically saved and will remain wh" +
                    "en Watcher is restarted.");
            this.autosavecheckBox.UseVisualStyleBackColor = true;
            this.autosavecheckBox.CheckedChanged += new System.EventHandler(this.autosavecheckBox_CheckedChanged);
            // 
            // watcherbackgroundbutton
            // 
            this.watcherbackgroundbutton.Location = new System.Drawing.Point(9, 21);
            this.watcherbackgroundbutton.Name = "watcherbackgroundbutton";
            this.watcherbackgroundbutton.Size = new System.Drawing.Size(106, 23);
            this.watcherbackgroundbutton.TabIndex = 0;
            this.watcherbackgroundbutton.Text = "Background Color";
            this.toolTipConfigControl.SetToolTip(this.watcherbackgroundbutton, "Set the background color for Watcher UI");
            this.watcherbackgroundbutton.UseVisualStyleBackColor = true;
            this.watcherbackgroundbutton.Click += new System.EventHandler(this.button1_Click);
            // 
            // ProcessOffline
            // 
            this.ProcessOffline.BackColor = System.Drawing.Color.Transparent;
            this.ProcessOffline.Location = new System.Drawing.Point(309, 5);
            this.ProcessOffline.Name = "ProcessOffline";
            this.ProcessOffline.Size = new System.Drawing.Size(138, 23);
            this.ProcessOffline.TabIndex = 2;
            this.ProcessOffline.Text = "Process Sessions Offline";
            this.toolTipConfigControl.SetToolTip(this.ProcessOffline, "Process a .saz file (session archive) loaded offline into Fiddler.\r\nFirst click F" +
                    "ile -> Load Archive in Fiddler\'s main menu to load the .saz file.");
            this.ProcessOffline.UseVisualStyleBackColor = true;
            this.ProcessOffline.Click += new System.EventHandler(this.ProcessOffline_Click);
            // 
            // pnlCopyright
            // 
            this.pnlCopyright.BackColor = System.Drawing.Color.Transparent;
            this.pnlCopyright.Controls.Add(this.rightslabel);
            this.pnlCopyright.Controls.Add(this.linkLabel1);
            this.pnlCopyright.Controls.Add(this.pbCasaba);
            this.pnlCopyright.Controls.Add(this.copyrightlabel);
            this.pnlCopyright.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.pnlCopyright.Location = new System.Drawing.Point(0, 545);
            this.pnlCopyright.Margin = new System.Windows.Forms.Padding(0);
            this.pnlCopyright.Name = "pnlCopyright";
            this.pnlCopyright.Size = new System.Drawing.Size(600, 55);
            this.pnlCopyright.TabIndex = 7;
            this.pnlCopyright.Paint += new System.Windows.Forms.PaintEventHandler(this.pnlCopyright_Paint);
            // 
            // rightslabel
            // 
            this.rightslabel.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom)
                        | System.Windows.Forms.AnchorStyles.Left)));
            this.rightslabel.AutoSize = true;
            this.rightslabel.Location = new System.Drawing.Point(500, 20);
            this.rightslabel.Margin = new System.Windows.Forms.Padding(1);
            this.rightslabel.Name = "rightslabel";
            this.rightslabel.Size = new System.Drawing.Size(93, 13);
            this.rightslabel.TabIndex = 6;
            this.rightslabel.Text = "All rights reserved.";
            // 
            // linkLabel1
            // 
            this.linkLabel1.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom)
                        | System.Windows.Forms.AnchorStyles.Left)));
            this.linkLabel1.AutoSize = true;
            this.linkLabel1.BackColor = System.Drawing.Color.Transparent;
            this.linkLabel1.Location = new System.Drawing.Point(385, 20);
            this.linkLabel1.Margin = new System.Windows.Forms.Padding(1);
            this.linkLabel1.Name = "linkLabel1";
            this.linkLabel1.Size = new System.Drawing.Size(112, 13);
            this.linkLabel1.TabIndex = 1;
            this.linkLabel1.TabStop = true;
            this.linkLabel1.Text = "Casaba Security, LLC.";
            this.linkLabel1.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.linkLabel_LinkClicked);
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
            this.copyrightlabel.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom)
                        | System.Windows.Forms.AnchorStyles.Left)));
            this.copyrightlabel.AutoSize = true;
            this.copyrightlabel.Location = new System.Drawing.Point(113, 20);
            this.copyrightlabel.Name = "copyrightlabel";
            this.copyrightlabel.Size = new System.Drawing.Size(228, 13);
            this.copyrightlabel.TabIndex = 0;
            this.copyrightlabel.Text = "Watcher Web Security Tool, Copyright © 2010";
            this.copyrightlabel.Click += new System.EventHandler(this.copyrightlabel_Click);
            // 
            // uigroupBox
            // 
            this.uigroupBox.Controls.Add(this.watcherbackgroundbutton);
            this.uigroupBox.Location = new System.Drawing.Point(3, 390);
            this.uigroupBox.Name = "uigroupBox";
            this.uigroupBox.Size = new System.Drawing.Size(479, 57);
            this.uigroupBox.TabIndex = 8;
            this.uigroupBox.TabStop = false;
            this.uigroupBox.Text = "User Interface";
            this.uigroupBox.Visible = false;
            this.uigroupBox.Enter += new System.EventHandler(this.uigroupBox_Enter);
            // 
            // pluginPanel
            // 
            this.pluginPanel.Location = new System.Drawing.Point(3, 335);
            this.pluginPanel.Name = "pluginPanel";
            this.pluginPanel.Size = new System.Drawing.Size(479, 40);
            this.pluginPanel.TabIndex = 9;
            // 
            // WatcherConfigControl
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.BackColor = System.Drawing.Color.Transparent;
            this.Controls.Add(this.ProcessOffline);
            this.Controls.Add(this.pluginPanel);
            this.Controls.Add(this.uigroupBox);
            this.Controls.Add(this.pnlCopyright);
            this.Controls.Add(this.appgroupBox);
            this.Controls.Add(this.configGroupBox);
            this.Controls.Add(this.enableCheckBox);
            this.Name = "WatcherConfigControl";
            this.Size = new System.Drawing.Size(600, 600);
            this.configGroupBox.ResumeLayout(false);
            this.configGroupBox.PerformLayout();
            this.appgroupBox.ResumeLayout(false);
            this.appgroupBox.PerformLayout();
            this.pnlCopyright.ResumeLayout(false);
            this.pnlCopyright.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.pbCasaba)).EndInit();
            this.uigroupBox.ResumeLayout(false);
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
        private System.Windows.Forms.Label lblDomainsAcceptRegularExpressions;
        public System.Windows.Forms.CheckBox enableCheckBox;
        public System.Windows.Forms.Button CheckLatestButton;
        private System.Windows.Forms.Button saveconfigbutton;
        private System.Windows.Forms.GroupBox appgroupBox;
        private System.Windows.Forms.CheckBox autovercheckBox;
        private System.Windows.Forms.CheckBox autosavecheckBox;
        private System.Windows.Forms.ToolTip toolTipConfigControl;
        private System.Windows.Forms.Panel pnlCopyright;
        private System.Windows.Forms.Label rightslabel;
        public System.Windows.Forms.LinkLabel linkLabel1;
        private System.Windows.Forms.PictureBox pbCasaba;
        private System.Windows.Forms.Label copyrightlabel;
        private System.Windows.Forms.GroupBox uigroupBox;
        private System.Windows.Forms.Button watcherbackgroundbutton;
        private System.Windows.Forms.ColorDialog colorDialog;
        private System.Windows.Forms.Panel pluginPanel;
        private System.Windows.Forms.Button ProcessOffline;
    }
}
