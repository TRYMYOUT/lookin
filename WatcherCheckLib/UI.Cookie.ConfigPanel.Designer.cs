// WATCHER
//
// UI.Enable.ConfigPanel.Designer.cs
//
// Copyright (c) 2009 Casaba Security, LLC
// All Rights Reserved.
//

namespace CasabaSecurity.Web.Watcher.Checks
{
    partial class CookieCheckConfigPanel
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
            this.enablefiltercheckBox = new System.Windows.Forms.CheckBox();
            this.cookiecheckgroupBox = new System.Windows.Forms.GroupBox();
            this.cookiegroupBox = new System.Windows.Forms.GroupBox();
            this.cookiechecklistBox = new System.Windows.Forms.ListView();
            this.deletebuttonpanel = new System.Windows.Forms.Panel();
            this.deletebutton = new System.Windows.Forms.Button();
            this.stringcheckgroupBox = new System.Windows.Forms.GroupBox();
            this.addbutton = new System.Windows.Forms.Button();
            this.cookiecheckentrytextBox = new System.Windows.Forms.TextBox();
            this.panel1 = new System.Windows.Forms.Panel();
            this.filtertypecomboBox = new System.Windows.Forms.ComboBox();
            this.cookiecheckgroupBox.SuspendLayout();
            this.cookiegroupBox.SuspendLayout();
            this.deletebuttonpanel.SuspendLayout();
            this.stringcheckgroupBox.SuspendLayout();
            this.panel1.SuspendLayout();
            this.SuspendLayout();
            // 
            // enablefiltercheckBox
            // 
            this.enablefiltercheckBox.AutoSize = true;
            this.enablefiltercheckBox.Location = new System.Drawing.Point(3, 8);
            this.enablefiltercheckBox.Name = "enablefiltercheckBox";
            this.enablefiltercheckBox.Size = new System.Drawing.Size(194, 17);
            this.enablefiltercheckBox.TabIndex = 0;
            this.enablefiltercheckBox.Text = "Filter cookies seen more than once.";
            this.enablefiltercheckBox.UseVisualStyleBackColor = true;
            this.enablefiltercheckBox.CheckedChanged += new System.EventHandler(this.enablefiltercheckBox_CheckedChanged);
            // 
            // cookiecheckgroupBox
            // 
            this.cookiecheckgroupBox.AutoSize = true;
            this.cookiecheckgroupBox.Controls.Add(this.cookiegroupBox);
            this.cookiecheckgroupBox.Controls.Add(this.stringcheckgroupBox);
            this.cookiecheckgroupBox.Controls.Add(this.panel1);
            this.cookiecheckgroupBox.Dock = System.Windows.Forms.DockStyle.Fill;
            this.cookiecheckgroupBox.Location = new System.Drawing.Point(0, 0);
            this.cookiecheckgroupBox.Name = "cookiecheckgroupBox";
            this.cookiecheckgroupBox.Size = new System.Drawing.Size(472, 283);
            this.cookiecheckgroupBox.TabIndex = 1;
            this.cookiecheckgroupBox.TabStop = false;
            this.cookiecheckgroupBox.Text = "Cookie Check Config";
            // 
            // cookiegroupBox
            // 
            this.cookiegroupBox.Controls.Add(this.cookiechecklistBox);
            this.cookiegroupBox.Controls.Add(this.deletebuttonpanel);
            this.cookiegroupBox.Dock = System.Windows.Forms.DockStyle.Fill;
            this.cookiegroupBox.Location = new System.Drawing.Point(3, 53);
            this.cookiegroupBox.Name = "cookiegroupBox";
            this.cookiegroupBox.Padding = new System.Windows.Forms.Padding(6);
            this.cookiegroupBox.Size = new System.Drawing.Size(466, 159);
            this.cookiegroupBox.TabIndex = 5;
            this.cookiegroupBox.TabStop = false;
            this.cookiegroupBox.Text = "Cookies to check:";
            // 
            // cookiechecklistBox
            // 
            this.cookiechecklistBox.AllowDrop = true;
            this.cookiechecklistBox.Dock = System.Windows.Forms.DockStyle.Fill;
            this.cookiechecklistBox.Location = new System.Drawing.Point(6, 19);
            this.cookiechecklistBox.Name = "cookiechecklistBox";
            this.cookiechecklistBox.Size = new System.Drawing.Size(454, 111);
            this.cookiechecklistBox.TabIndex = 0;
            this.cookiechecklistBox.UseCompatibleStateImageBehavior = false;
            this.cookiechecklistBox.View = System.Windows.Forms.View.List;
            // 
            // deletebuttonpanel
            // 
            this.deletebuttonpanel.Controls.Add(this.deletebutton);
            this.deletebuttonpanel.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.deletebuttonpanel.Location = new System.Drawing.Point(6, 130);
            this.deletebuttonpanel.Margin = new System.Windows.Forms.Padding(3, 3, 3, 0);
            this.deletebuttonpanel.Name = "deletebuttonpanel";
            this.deletebuttonpanel.Size = new System.Drawing.Size(454, 23);
            this.deletebuttonpanel.TabIndex = 3;
            // 
            // deletebutton
            // 
            this.deletebutton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.deletebutton.Location = new System.Drawing.Point(0, 1);
            this.deletebutton.Name = "deletebutton";
            this.deletebutton.Size = new System.Drawing.Size(75, 23);
            this.deletebutton.TabIndex = 2;
            this.deletebutton.Text = "Delete";
            this.deletebutton.UseVisualStyleBackColor = true;
            this.deletebutton.Click += new System.EventHandler(this.deletebutton_Click);
            // 
            // stringcheckgroupBox
            // 
            this.stringcheckgroupBox.Controls.Add(this.addbutton);
            this.stringcheckgroupBox.Controls.Add(this.cookiecheckentrytextBox);
            this.stringcheckgroupBox.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.stringcheckgroupBox.Location = new System.Drawing.Point(3, 212);
            this.stringcheckgroupBox.Name = "stringcheckgroupBox";
            this.stringcheckgroupBox.Size = new System.Drawing.Size(466, 68);
            this.stringcheckgroupBox.TabIndex = 4;
            this.stringcheckgroupBox.TabStop = false;
            this.stringcheckgroupBox.Text = "Cookie name to add:";
            // 
            // addbutton
            // 
            this.addbutton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.addbutton.Location = new System.Drawing.Point(3, 40);
            this.addbutton.Name = "addbutton";
            this.addbutton.Size = new System.Drawing.Size(75, 23);
            this.addbutton.TabIndex = 1;
            this.addbutton.Text = "Add";
            this.addbutton.UseVisualStyleBackColor = true;
            this.addbutton.Click += new System.EventHandler(this.addbutton_Click);
            // 
            // cookiecheckentrytextBox
            // 
            this.cookiecheckentrytextBox.Dock = System.Windows.Forms.DockStyle.Top;
            this.cookiecheckentrytextBox.Location = new System.Drawing.Point(3, 16);
            this.cookiecheckentrytextBox.Name = "cookiecheckentrytextBox";
            this.cookiecheckentrytextBox.Size = new System.Drawing.Size(460, 20);
            this.cookiecheckentrytextBox.TabIndex = 0;
            // 
            // panel1
            // 
            this.panel1.Controls.Add(this.filtertypecomboBox);
            this.panel1.Controls.Add(this.enablefiltercheckBox);
            this.panel1.Dock = System.Windows.Forms.DockStyle.Top;
            this.panel1.Location = new System.Drawing.Point(3, 16);
            this.panel1.Name = "panel1";
            this.panel1.Size = new System.Drawing.Size(466, 37);
            this.panel1.TabIndex = 1;
            // 
            // filtertypecomboBox
            // 
            this.filtertypecomboBox.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.filtertypecomboBox.FormattingEnabled = true;
            this.filtertypecomboBox.Items.AddRange(new object[] {
            "Inclusive Filter",
            "Exclusive Filter"});
            this.filtertypecomboBox.Location = new System.Drawing.Point(339, 6);
            this.filtertypecomboBox.Name = "filtertypecomboBox";
            this.filtertypecomboBox.Size = new System.Drawing.Size(121, 21);
            this.filtertypecomboBox.TabIndex = 1;
            this.filtertypecomboBox.Text = "Inclusive Filter";
            this.filtertypecomboBox.SelectedIndexChanged += new System.EventHandler(this.filtertypecomboBox_SelectedIndexChanged);
            // 
            // CookieCheckConfigPanel
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.cookiecheckgroupBox);
            this.Name = "CookieCheckConfigPanel";
            this.Size = new System.Drawing.Size(472, 283);
            this.cookiecheckgroupBox.ResumeLayout(false);
            this.cookiegroupBox.ResumeLayout(false);
            this.deletebuttonpanel.ResumeLayout(false);
            this.stringcheckgroupBox.ResumeLayout(false);
            this.stringcheckgroupBox.PerformLayout();
            this.panel1.ResumeLayout(false);
            this.panel1.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        public System.Windows.Forms.CheckBox enablefiltercheckBox;
        private System.Windows.Forms.GroupBox cookiecheckgroupBox;
        private System.Windows.Forms.Panel panel1;
        private System.Windows.Forms.GroupBox stringcheckgroupBox;
        private System.Windows.Forms.Button addbutton;
        private System.Windows.Forms.TextBox cookiecheckentrytextBox;
        private System.Windows.Forms.GroupBox cookiegroupBox;
        public System.Windows.Forms.ListView cookiechecklistBox;
        private System.Windows.Forms.Panel deletebuttonpanel;
        private System.Windows.Forms.Button deletebutton;
        private System.Windows.Forms.ComboBox filtertypecomboBox;
    }
}
