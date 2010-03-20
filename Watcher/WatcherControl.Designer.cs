// WATCHER
//
// WatcherControl.Designer.cs
// Implementation of WatcherControl UI.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

namespace CasabaSecurity.Web.Watcher
{
    partial class WatcherControl
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
            this.watchertabControl = new System.Windows.Forms.TabControl();
            this.tabPage1 = new System.Windows.Forms.TabPage();
            this.watcherConfigTab = new CasabaSecurity.Web.Watcher.WatcherConfigControl();
            this.tabPage3 = new System.Windows.Forms.TabPage();
            this.watcherCheckTab = new CasabaSecurity.Web.Watcher.WatcherCheckControl();
            this.tabPage2 = new System.Windows.Forms.TabPage();
            this.watcherResultsTab = new CasabaSecurity.Web.Watcher.WatcherResultsControl();
            this.watchertabControl.SuspendLayout();
            this.tabPage1.SuspendLayout();
            this.tabPage3.SuspendLayout();
            this.tabPage2.SuspendLayout();
            this.SuspendLayout();
            // 
            // watchertabControl
            // 
            this.watchertabControl.Controls.Add(this.tabPage1);
            this.watchertabControl.Controls.Add(this.tabPage3);
            this.watchertabControl.Controls.Add(this.tabPage2);
            this.watchertabControl.Dock = System.Windows.Forms.DockStyle.Fill;
            this.watchertabControl.Location = new System.Drawing.Point(0, 0);
            this.watchertabControl.Margin = new System.Windows.Forms.Padding(0);
            this.watchertabControl.Name = "watchertabControl";
            this.watchertabControl.Padding = new System.Drawing.Point(0, 0);
            this.watchertabControl.SelectedIndex = 0;
            this.watchertabControl.Size = new System.Drawing.Size(600, 600);
            this.watchertabControl.TabIndex = 0;
            // 
            // tabPage1
            // 
            //this.tabPage1.BackColor = System.Drawing.SystemColors.Window;
            this.tabPage1.BackColor = System.Drawing.Color.Transparent;
            this.tabPage1.Controls.Add(this.watcherConfigTab);
            this.tabPage1.Location = new System.Drawing.Point(4, 22);
            this.tabPage1.Name = "tabPage1";
            this.tabPage1.Size = new System.Drawing.Size(592, 574);
            this.tabPage1.TabIndex = 0;
            this.tabPage1.Text = "Configuration";
            // 
            // watcherConfigTab
            // 
            this.watcherConfigTab.AutoScroll = true;
            this.watcherConfigTab.BackColor = System.Drawing.Color.Transparent;
            this.watcherConfigTab.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.watcherConfigTab.Dock = System.Windows.Forms.DockStyle.Fill;
            this.watcherConfigTab.Location = new System.Drawing.Point(0, 0);
            this.watcherConfigTab.Margin = new System.Windows.Forms.Padding(0);
            this.watcherConfigTab.Name = "watcherConfigTab";
            this.watcherConfigTab.Size = new System.Drawing.Size(592, 574);
            this.watcherConfigTab.TabIndex = 0;
            // 
            // tabPage3
            // 
            //this.tabPage3.BackColor = System.Drawing.SystemColors.Window;
            this.tabPage3.BackColor = System.Drawing.Color.Transparent;
            this.tabPage3.Controls.Add(this.watcherCheckTab);
            this.tabPage3.Location = new System.Drawing.Point(4, 22);
            this.tabPage3.Name = "tabPage3";
            this.tabPage3.Size = new System.Drawing.Size(592, 574);
            this.tabPage3.TabIndex = 2;
            this.tabPage3.Text = "Checks";
            // 
            // watcherCheckTab
            // 
            this.watcherCheckTab.AutoScroll = true;
            this.watcherCheckTab.BackColor = System.Drawing.Color.Transparent;
            this.watcherCheckTab.Dock = System.Windows.Forms.DockStyle.Fill;
            this.watcherCheckTab.Location = new System.Drawing.Point(0, 0);
            this.watcherCheckTab.Name = "watcherCheckTab";
            this.watcherCheckTab.Size = new System.Drawing.Size(592, 574);
            this.watcherCheckTab.TabIndex = 0;
            // 
            // tabPage2
            // 
            //this.tabPage2.BackColor = System.Drawing.SystemColors.Window;
            this.tabPage2.BackColor = System.Drawing.Color.Transparent;
            this.tabPage2.Controls.Add(this.watcherResultsTab);
            this.tabPage2.Location = new System.Drawing.Point(4, 22);
            this.tabPage2.Margin = new System.Windows.Forms.Padding(0);
            this.tabPage2.Name = "tabPage2";
            this.tabPage2.Size = new System.Drawing.Size(592, 574);
            this.tabPage2.TabIndex = 1;
            this.tabPage2.Text = "Results";
            // 
            // watcherResultsTab
            // 
            this.watcherResultsTab.BackColor = System.Drawing.Color.Transparent;
            this.watcherResultsTab.Dock = System.Windows.Forms.DockStyle.Fill;
            this.watcherResultsTab.Location = new System.Drawing.Point(0, 0);
            this.watcherResultsTab.Margin = new System.Windows.Forms.Padding(0);
            this.watcherResultsTab.Name = "watcherResultsTab";
            this.watcherResultsTab.Size = new System.Drawing.Size(592, 574);
            this.watcherResultsTab.TabIndex = 0;
            // 
            // WatcherControl
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            //this.BackColor = System.Drawing.SystemColors.Window;
            this.BackColor = System.Drawing.Color.Transparent;
            this.Controls.Add(this.watchertabControl);
            this.Name = "WatcherControl";
            this.Size = new System.Drawing.Size(600, 600);
            this.watchertabControl.ResumeLayout(false);
            this.tabPage1.ResumeLayout(false);
            this.tabPage3.ResumeLayout(false);
            this.tabPage2.ResumeLayout(false);
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.TabControl watchertabControl;
        public CasabaSecurity.Web.Watcher.WatcherConfigControl watcherConfigTab; 
        public CasabaSecurity.Web.Watcher.WatcherCheckControl watcherCheckTab;
        public CasabaSecurity.Web.Watcher.WatcherResultsControl watcherResultsTab;
        private System.Windows.Forms.TabPage tabPage1;
        private System.Windows.Forms.TabPage tabPage2;
        private System.Windows.Forms.TabPage tabPage3;
    }
}