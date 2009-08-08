// WATCHER
//
// UI.InformationDisclosure.ConfigPanel.Designer.cs
//
// Copyright (c) 2009 Casaba Security, LLC
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
            this.stringchecksplitContainer = new System.Windows.Forms.SplitContainer();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.stringchecklistBox = new System.Windows.Forms.ListView();
            this.deletebuttonpanel = new System.Windows.Forms.Panel();
            this.deletebutton = new System.Windows.Forms.Button();
            this.stringcheckgroupBox = new System.Windows.Forms.GroupBox();
            this.addbutton = new System.Windows.Forms.Button();
            this.stringcheckentrytextBox = new System.Windows.Forms.TextBox();
            this.stringchecksplitContainer.Panel1.SuspendLayout();
            this.stringchecksplitContainer.Panel2.SuspendLayout();
            this.stringchecksplitContainer.SuspendLayout();
            this.groupBox1.SuspendLayout();
            this.deletebuttonpanel.SuspendLayout();
            this.stringcheckgroupBox.SuspendLayout();
            this.SuspendLayout();
            // 
            // stringchecksplitContainer
            // 
            this.stringchecksplitContainer.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.stringchecksplitContainer.Dock = System.Windows.Forms.DockStyle.Fill;
            this.stringchecksplitContainer.FixedPanel = System.Windows.Forms.FixedPanel.Panel2;
            this.stringchecksplitContainer.Location = new System.Drawing.Point(0, 0);
            this.stringchecksplitContainer.Name = "stringchecksplitContainer";
            this.stringchecksplitContainer.Orientation = System.Windows.Forms.Orientation.Horizontal;
            // 
            // stringchecksplitContainer.Panel1
            // 
            this.stringchecksplitContainer.Panel1.Controls.Add(this.groupBox1);
            this.stringchecksplitContainer.Panel1.Padding = new System.Windows.Forms.Padding(3);
            // 
            // stringchecksplitContainer.Panel2
            // 
            this.stringchecksplitContainer.Panel2.Controls.Add(this.stringcheckgroupBox);
            this.stringchecksplitContainer.Panel2.Padding = new System.Windows.Forms.Padding(3);
            this.stringchecksplitContainer.Size = new System.Drawing.Size(553, 237);
            this.stringchecksplitContainer.SplitterDistance = 156;
            this.stringchecksplitContainer.TabIndex = 0;
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.stringchecklistBox);
            this.groupBox1.Controls.Add(this.deletebuttonpanel);
            this.groupBox1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.groupBox1.Location = new System.Drawing.Point(3, 3);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Padding = new System.Windows.Forms.Padding(6);
            this.groupBox1.Size = new System.Drawing.Size(545, 148);
            this.groupBox1.TabIndex = 1;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "String Check Replace";
            // 
            // stringchecklistBox
            // 
            this.stringchecklistBox.AllowDrop = true;
            this.stringchecklistBox.Dock = System.Windows.Forms.DockStyle.Fill;
            this.stringchecklistBox.Location = new System.Drawing.Point(6, 19);
            this.stringchecklistBox.Name = "stringchecklistBox";
            this.stringchecklistBox.Size = new System.Drawing.Size(533, 100);
            this.stringchecklistBox.TabIndex = 0;
            this.stringchecklistBox.UseCompatibleStateImageBehavior = false;
            this.stringchecklistBox.View = System.Windows.Forms.View.List;
            // 
            // deletebuttonpanel
            // 
            this.deletebuttonpanel.Controls.Add(this.deletebutton);
            this.deletebuttonpanel.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.deletebuttonpanel.Location = new System.Drawing.Point(6, 119);
            this.deletebuttonpanel.Margin = new System.Windows.Forms.Padding(3, 3, 3, 0);
            this.deletebuttonpanel.Name = "deletebuttonpanel";
            this.deletebuttonpanel.Size = new System.Drawing.Size(533, 23);
            this.deletebuttonpanel.TabIndex = 3;
            // 
            // deletebutton
            // 
            this.deletebutton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.deletebutton.Location = new System.Drawing.Point(0, 1);
            this.deletebutton.Margin = new System.Windows.Forms.Padding(6);
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
            this.stringcheckgroupBox.Controls.Add(this.stringcheckentrytextBox);
            this.stringcheckgroupBox.Dock = System.Windows.Forms.DockStyle.Fill;
            this.stringcheckgroupBox.Location = new System.Drawing.Point(3, 3);
            this.stringcheckgroupBox.Name = "stringcheckgroupBox";
            this.stringcheckgroupBox.Size = new System.Drawing.Size(545, 69);
            this.stringcheckgroupBox.TabIndex = 3;
            this.stringcheckgroupBox.TabStop = false;
            this.stringcheckgroupBox.Text = "String Check Replace Strings:";
            // 
            // addbutton
            // 
            this.addbutton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.addbutton.Location = new System.Drawing.Point(3, 38);
            this.addbutton.Margin = new System.Windows.Forms.Padding(6);
            this.addbutton.Name = "addbutton";
            this.addbutton.Size = new System.Drawing.Size(75, 23);
            this.addbutton.TabIndex = 1;
            this.addbutton.Text = "Add";
            this.addbutton.UseVisualStyleBackColor = true;
            this.addbutton.Click += new System.EventHandler(this.addbutton_Click);
            // 
            // stringcheckentrytextBox
            // 
            this.stringcheckentrytextBox.Dock = System.Windows.Forms.DockStyle.Top;
            this.stringcheckentrytextBox.Location = new System.Drawing.Point(3, 16);
            this.stringcheckentrytextBox.Name = "stringcheckentrytextBox";
            this.stringcheckentrytextBox.Size = new System.Drawing.Size(539, 20);
            this.stringcheckentrytextBox.TabIndex = 0;
            // 
            // StringCheckConfigPanel
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.AutoSize = true;
            this.Controls.Add(this.stringchecksplitContainer);
            this.Name = "StringCheckConfigPanel";
            this.Size = new System.Drawing.Size(553, 237);
            this.stringchecksplitContainer.Panel1.ResumeLayout(false);
            this.stringchecksplitContainer.Panel2.ResumeLayout(false);
            this.stringchecksplitContainer.ResumeLayout(false);
            this.groupBox1.ResumeLayout(false);
            this.deletebuttonpanel.ResumeLayout(false);
            this.stringcheckgroupBox.ResumeLayout(false);
            this.stringcheckgroupBox.PerformLayout();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.SplitContainer stringchecksplitContainer;
        private System.Windows.Forms.TextBox stringcheckentrytextBox;
        private System.Windows.Forms.Button deletebutton;
        private System.Windows.Forms.Button addbutton;
        private System.Windows.Forms.GroupBox stringcheckgroupBox;
        public System.Windows.Forms.ListView stringchecklistBox;
        private GroupBox groupBox1;
        private Panel deletebuttonpanel;
    }
}
