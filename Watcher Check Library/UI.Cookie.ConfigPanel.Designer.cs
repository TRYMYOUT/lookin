// WATCHER
//
// UI.Enable.ConfigPanel.Designer.cs
//
// Copyright (c) 2010 Casaba Security, LLC
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
            this.components = new System.ComponentModel.Container();
            this.cookiecheckgroupBox = new System.Windows.Forms.GroupBox();
            this.cookiechecklistBox = new System.Windows.Forms.ListView();
            this.cookiecheckentrytextBox = new System.Windows.Forms.TextBox();
            this.label2 = new System.Windows.Forms.Label();
            this.addbutton = new System.Windows.Forms.Button();
            this.enablefiltercheckBox = new System.Windows.Forms.CheckBox();
            this.filtertypecomboBox = new System.Windows.Forms.ComboBox();
            this.lblCookies = new System.Windows.Forms.Label();
            this.deletebutton = new System.Windows.Forms.Button();
            this.toolTipCookieConfigUI = new System.Windows.Forms.ToolTip(this.components);
            this.cookiecheckgroupBox.SuspendLayout();
            this.SuspendLayout();
            // 
            // cookiecheckgroupBox
            // 
            this.cookiecheckgroupBox.AutoSize = true;
            this.cookiecheckgroupBox.Controls.Add(this.cookiechecklistBox);
            this.cookiecheckgroupBox.Controls.Add(this.cookiecheckentrytextBox);
            this.cookiecheckgroupBox.Controls.Add(this.label2);
            this.cookiecheckgroupBox.Controls.Add(this.addbutton);
            this.cookiecheckgroupBox.Controls.Add(this.enablefiltercheckBox);
            this.cookiecheckgroupBox.Controls.Add(this.filtertypecomboBox);
            this.cookiecheckgroupBox.Controls.Add(this.lblCookies);
            this.cookiecheckgroupBox.Controls.Add(this.deletebutton);
            this.cookiecheckgroupBox.Dock = System.Windows.Forms.DockStyle.Fill;
            this.cookiecheckgroupBox.Location = new System.Drawing.Point(0, 0);
            this.cookiecheckgroupBox.Name = "cookiecheckgroupBox";
            this.cookiecheckgroupBox.Size = new System.Drawing.Size(472, 283);
            this.cookiecheckgroupBox.TabIndex = 0;
            this.cookiecheckgroupBox.TabStop = false;
            this.cookiecheckgroupBox.Text = "Check Configuration";
            // 
            // cookiechecklistBox
            // 
            this.cookiechecklistBox.AllowDrop = true;
            this.cookiechecklistBox.Location = new System.Drawing.Point(6, 140);
            this.cookiechecklistBox.Name = "cookiechecklistBox";
            this.cookiechecklistBox.Size = new System.Drawing.Size(460, 75);
            this.cookiechecklistBox.TabIndex = 7;
            this.cookiechecklistBox.UseCompatibleStateImageBehavior = false;
            this.cookiechecklistBox.View = System.Windows.Forms.View.List;
            // 
            // cookiecheckentrytextBox
            // 
            this.cookiecheckentrytextBox.Location = new System.Drawing.Point(6, 64);
            this.cookiecheckentrytextBox.Name = "cookiecheckentrytextBox";
            this.cookiecheckentrytextBox.Size = new System.Drawing.Size(463, 20);
            this.cookiecheckentrytextBox.TabIndex = 3;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(3, 48);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(105, 13);
            this.label2.TabIndex = 2;
            this.label2.Text = "Cookie name to add:";
            // 
            // addbutton
            // 
            this.addbutton.Location = new System.Drawing.Point(6, 90);
            this.addbutton.Name = "addbutton";
            this.addbutton.Size = new System.Drawing.Size(75, 23);
            this.addbutton.TabIndex = 4;
            this.addbutton.Text = "Add";
            this.toolTipCookieConfigUI.SetToolTip(this.addbutton, "Adds the cookie in the text box to the non-duplicate filter. ");
            this.addbutton.UseVisualStyleBackColor = true;
            this.addbutton.Click += new System.EventHandler(this.addbutton_Click);
            // 
            // enablefiltercheckBox
            // 
            this.enablefiltercheckBox.AutoSize = true;
            this.enablefiltercheckBox.Location = new System.Drawing.Point(6, 19);
            this.enablefiltercheckBox.Name = "enablefiltercheckBox";
            this.enablefiltercheckBox.Size = new System.Drawing.Size(191, 17);
            this.enablefiltercheckBox.TabIndex = 0;
            this.enablefiltercheckBox.Text = "Filter cookies seen more than once";
            this.toolTipCookieConfigUI.SetToolTip(this.enablefiltercheckBox, "Filters out duplicate cookies. For example, cookies that are set to a new value e" +
                    "very request will only be reported the first time seen..");
            this.enablefiltercheckBox.UseVisualStyleBackColor = true;
            // 
            // filtertypecomboBox
            // 
            this.filtertypecomboBox.FormattingEnabled = true;
            this.filtertypecomboBox.Items.AddRange(new object[] {
            "Inclusive Filter",
            "Exclusive Filter"});
            this.filtertypecomboBox.Location = new System.Drawing.Point(345, 19);
            this.filtertypecomboBox.Name = "filtertypecomboBox";
            this.filtertypecomboBox.Size = new System.Drawing.Size(121, 21);
            this.filtertypecomboBox.TabIndex = 1;
            this.filtertypecomboBox.Text = "Inclusive Filter";
            this.toolTipCookieConfigUI.SetToolTip(this.filtertypecomboBox, "Specifies whether the non-duplicate filter is inclusive or exclusive. Inclusive a" +
                    "nalyzes only the cookies listed (must be at least one). Exclusive analyzes all c" +
                    "ookies except those listed.");
            this.filtertypecomboBox.SelectedIndexChanged += new System.EventHandler(this.filtertypecomboBox_SelectedIndexChanged);
            // 
            // lblCookies
            // 
            this.lblCookies.AutoSize = true;
            this.lblCookies.BackColor = System.Drawing.Color.Transparent;
            this.lblCookies.Location = new System.Drawing.Point(3, 124);
            this.lblCookies.Name = "lblCookies";
            this.lblCookies.Size = new System.Drawing.Size(99, 13);
            this.lblCookies.TabIndex = 6;
            this.lblCookies.Text = "Cookies to analyze:";
            // 
            // deletebutton
            // 
            this.deletebutton.Location = new System.Drawing.Point(87, 90);
            this.deletebutton.Name = "deletebutton";
            this.deletebutton.Size = new System.Drawing.Size(75, 23);
            this.deletebutton.TabIndex = 5;
            this.deletebutton.Text = "Remove";
            this.toolTipCookieConfigUI.SetToolTip(this.deletebutton, "Removes selected cookies from the cookie list.");
            this.deletebutton.UseVisualStyleBackColor = true;
            this.deletebutton.Click += new System.EventHandler(this.deletebutton_Click);
            // 
            // CookieCheckConfigPanel
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.cookiecheckgroupBox);
            this.Name = "CookieCheckConfigPanel";
            this.Size = new System.Drawing.Size(472, 283);
            this.cookiecheckgroupBox.ResumeLayout(false);
            this.cookiecheckgroupBox.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.GroupBox cookiecheckgroupBox;
        private System.Windows.Forms.Button addbutton;
        private System.Windows.Forms.ComboBox filtertypecomboBox;
        public System.Windows.Forms.ListView cookiechecklistBox;
        private System.Windows.Forms.Button deletebutton;
        private System.Windows.Forms.Label lblCookies;
        private System.Windows.Forms.TextBox cookiecheckentrytextBox;
        public System.Windows.Forms.CheckBox enablefiltercheckBox;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.ToolTip toolTipCookieConfigUI;
    }
}
