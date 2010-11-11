// WATCHER
//
// UI.InformationDisclosure.ConfigPanel.Designer.cs
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System.Windows.Forms;

namespace CasabaSecurity.Web.Watcher.Checks
{
    partial class StringCheckConfigPanel 
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
            this.btnRemove = new System.Windows.Forms.Button();
            this.addbutton = new System.Windows.Forms.Button();
            this.stringcheckentrytextBox = new System.Windows.Forms.TextBox();
            this.lblReplacementString = new System.Windows.Forms.Label();
            this.groupBox2 = new System.Windows.Forms.GroupBox();
            this.stringchecklistBox = new System.Windows.Forms.ListView();
            this.textpanel = new System.Windows.Forms.Panel();
            this.lblReplacementStrings = new System.Windows.Forms.Label();
            this.toolTipInformationDisclosureUI = new System.Windows.Forms.ToolTip(this.components);
            this.groupBox2.SuspendLayout();
            this.textpanel.SuspendLayout();
            this.SuspendLayout();
            // 
            // btnRemove
            // 
            this.btnRemove.Location = new System.Drawing.Point(104, 54);
            this.btnRemove.Margin = new System.Windows.Forms.Padding(6);
            this.btnRemove.Name = "btnRemove";
            this.btnRemove.Size = new System.Drawing.Size(75, 23);
            this.btnRemove.TabIndex = 3;
            this.btnRemove.Text = "Remove";
            this.btnRemove.UseVisualStyleBackColor = true;
            this.btnRemove.Click +=new System.EventHandler(deletebutton_Click);

            // 
            // addbutton
            // 
            this.addbutton.Location = new System.Drawing.Point(17, 54);
            this.addbutton.Margin = new System.Windows.Forms.Padding(6);
            this.addbutton.Name = "addbutton";
            this.addbutton.Size = new System.Drawing.Size(75, 23);
            this.addbutton.TabIndex = 2;
            this.addbutton.Text = "Add";
            this.addbutton.UseVisualStyleBackColor = true;
            this.addbutton.Click += new System.EventHandler(addbutton_Click);
            // 
            // stringcheckentrytextBox
            // 
            this.stringcheckentrytextBox.Location = new System.Drawing.Point(17, 28);
            this.stringcheckentrytextBox.Name = "stringcheckentrytextBox";
            this.stringcheckentrytextBox.Size = new System.Drawing.Size(536, 20);
            this.stringcheckentrytextBox.TabIndex = 1;
            // 
            // lblReplacementString
            // 
            this.lblReplacementString.AutoSize = true;
            this.lblReplacementString.Location = new System.Drawing.Point(14, 9);
            this.lblReplacementString.Name = "lblReplacementString";
            this.lblReplacementString.Size = new System.Drawing.Size(188, 13);
            this.lblReplacementString.TabIndex = 0;
            this.lblReplacementString.Text = "This text will be replaced by the check";
            // 
            // groupBox2
            // 
            this.groupBox2.Controls.Add(this.stringchecklistBox);
            this.groupBox2.Controls.Add(this.textpanel);
            this.groupBox2.Dock = System.Windows.Forms.DockStyle.Fill;
            this.groupBox2.Location = new System.Drawing.Point(0, 0);
            this.groupBox2.Name = "groupBox2";
            this.groupBox2.Size = new System.Drawing.Size(566, 277);
            this.groupBox2.TabIndex = 0;
            this.groupBox2.TabStop = false;
            this.groupBox2.Text = "Check Configuration";
            // 
            // stringchecklistBox
            // 
            this.stringchecklistBox.AllowDrop = true;
            this.stringchecklistBox.Dock = System.Windows.Forms.DockStyle.Fill;
            this.stringchecklistBox.Location = new System.Drawing.Point(3, 119);
            this.stringchecklistBox.Name = "stringchecklistBox";
            this.stringchecklistBox.Size = new System.Drawing.Size(560, 155);
            this.stringchecklistBox.TabIndex = 5;
            this.stringchecklistBox.UseCompatibleStateImageBehavior = false;
            this.stringchecklistBox.View = System.Windows.Forms.View.List;
            // 
            // textpanel
            // 
            this.textpanel.Controls.Add(this.lblReplacementString);
            this.textpanel.Controls.Add(this.addbutton);
            this.textpanel.Controls.Add(this.stringcheckentrytextBox);
            this.textpanel.Controls.Add(this.btnRemove);
            this.textpanel.Controls.Add(this.lblReplacementStrings);
            this.textpanel.Dock = System.Windows.Forms.DockStyle.Top;
            this.textpanel.Location = new System.Drawing.Point(3, 16);
            this.textpanel.Name = "textpanel";
            this.textpanel.Size = new System.Drawing.Size(560, 103);
            this.textpanel.TabIndex = 6;
            // 
            // lblReplacementStrings
            // 
            this.lblReplacementStrings.AutoSize = true;
            this.lblReplacementStrings.Location = new System.Drawing.Point(14, 83);
            this.lblReplacementStrings.Name = "lblReplacementStrings";
            this.lblReplacementStrings.Size = new System.Drawing.Size(210, 13);
            this.lblReplacementStrings.TabIndex = 4;
            this.lblReplacementStrings.Text = "This text will also be replaced by the check";
            // 
            // StringCheckConfigPanel
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.AutoSize = true;
            this.Controls.Add(this.groupBox2);
            this.Name = "StringCheckConfigPanel";
            this.Size = new System.Drawing.Size(566, 277);
            this.groupBox2.ResumeLayout(false);
            this.textpanel.ResumeLayout(false);
            this.textpanel.PerformLayout();
            this.ResumeLayout(false);

        }

        #endregion

        private Button btnRemove;
        private Button addbutton;
        private TextBox stringcheckentrytextBox;
        private Label lblReplacementString;
        private GroupBox groupBox2;
        public ListView stringchecklistBox;
        private Label lblReplacementStrings;
        private Panel textpanel;
        private ToolTip toolTipInformationDisclosureUI;
    }
}
