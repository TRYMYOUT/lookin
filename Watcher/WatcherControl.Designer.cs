// WATCHER
//
// WatcherControl.Designer.cs
// Implementation of WatcherControl UI.
//
// Copyright (c) 2009 Casaba Security, LLC
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
            this.watcherConfig = new CasabaSecurity.Web.Watcher.WatcherConfigControl();
            this.tabPage2 = new System.Windows.Forms.TabPage();
            this.watcherResultsTab = new CasabaSecurity.Web.Watcher.WatcherResultsControl();
            this.watchertabControl.SuspendLayout();
            this.tabPage1.SuspendLayout();
            this.tabPage2.SuspendLayout();
            this.SuspendLayout();
            // 
            // watchertabControl
            // 
            this.watchertabControl.Controls.Add(this.tabPage1);
            this.watchertabControl.Controls.Add(this.tabPage2);
            this.watchertabControl.Dock = System.Windows.Forms.DockStyle.Fill;
            this.watchertabControl.Location = new System.Drawing.Point(0, 0);
            this.watchertabControl.Margin = new System.Windows.Forms.Padding(0);
            this.watchertabControl.Name = "watchertabControl";
            this.watchertabControl.Padding = new System.Drawing.Point(0, 0);
            this.watchertabControl.SelectedIndex = 0;
            this.watchertabControl.Size = new System.Drawing.Size(881, 638);
            this.watchertabControl.TabIndex = 0;
            // 
            // tabPage1
            // 
            this.tabPage1.BackColor = System.Drawing.Color.LightGray;
            this.tabPage1.Controls.Add(this.watcherConfig);
            this.tabPage1.Location = new System.Drawing.Point(4, 22);
            this.tabPage1.Name = "tabPage1";
            this.tabPage1.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage1.Size = new System.Drawing.Size(873, 612);
            this.tabPage1.TabIndex = 0;
            this.tabPage1.Text = "Configuration";
            this.tabPage1.UseVisualStyleBackColor = true;
            // 
            // watcherConfig
            // 
            this.watcherConfig.AutoScroll = true;
            this.watcherConfig.BackColor = System.Drawing.Color.LightGray;
            this.watcherConfig.Dock = System.Windows.Forms.DockStyle.Fill;
            this.watcherConfig.Location = new System.Drawing.Point(3, 3);
            this.watcherConfig.Margin = new System.Windows.Forms.Padding(0);
            this.watcherConfig.Name = "watcherConfig";
            this.watcherConfig.Size = new System.Drawing.Size(867, 606);
            this.watcherConfig.TabIndex = 0;
            // 
            // tabPage2
            // 
            this.tabPage2.BackColor = System.Drawing.SystemColors.ControlLight;
            this.tabPage2.Controls.Add(this.watcherResultsTab);
            this.tabPage2.Location = new System.Drawing.Point(4, 22);
            this.tabPage2.Margin = new System.Windows.Forms.Padding(0);
            this.tabPage2.Name = "tabPage2";
            this.tabPage2.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage2.Size = new System.Drawing.Size(873, 612);
            this.tabPage2.TabIndex = 1;
            this.tabPage2.Text = "Results";
            this.tabPage2.UseVisualStyleBackColor = true;
            // 
            // watcherResultsTab
            // 
            this.watcherResultsTab.BackColor = System.Drawing.Color.LightGray;
            this.watcherResultsTab.Dock = System.Windows.Forms.DockStyle.Fill;
            this.watcherResultsTab.Location = new System.Drawing.Point(3, 3);
            this.watcherResultsTab.Margin = new System.Windows.Forms.Padding(0);
            this.watcherResultsTab.Name = "watcherResultsTab";
            this.watcherResultsTab.Size = new System.Drawing.Size(867, 606);
            this.watcherResultsTab.TabIndex = 0;
            // 
            // WatcherControl
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.watchertabControl);
            this.Name = "WatcherControl";
            this.Size = new System.Drawing.Size(881, 638);
            this.watchertabControl.ResumeLayout(false);
            this.tabPage1.ResumeLayout(false);
            this.tabPage2.ResumeLayout(false);
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.TabControl watchertabControl;
        public CasabaSecurity.Web.Watcher.WatcherConfigControl watcherConfig; 
        private System.Windows.Forms.TabPage tabPage1;
        public CasabaSecurity.Web.Watcher.WatcherResultsControl watcherResultsTab;
        private System.Windows.Forms.TabPage tabPage2;
    }
}