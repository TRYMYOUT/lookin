namespace CasabaSecurity.Web.Watcher.Checks
{
    partial class EnableCheckConfigPanel
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
            this.enablefiltercheckBox = new System.Windows.Forms.CheckBox();
            this.cookiecheckgroupBox = new System.Windows.Forms.GroupBox();
            this.toolTipEnableConfigUI = new System.Windows.Forms.ToolTip(this.components);
            this.cookiecheckgroupBox.SuspendLayout();
            this.SuspendLayout();
            // 
            // enablefiltercheckBox
            // 
            this.enablefiltercheckBox.AutoSize = true;
            this.enablefiltercheckBox.Location = new System.Drawing.Point(6, 19);
            this.enablefiltercheckBox.Name = "enablefiltercheckBox";
            this.enablefiltercheckBox.Size = new System.Drawing.Size(212, 17);
            this.enablefiltercheckBox.TabIndex = 0;
            this.enablefiltercheckBox.Text = "Enable filter for previously seen cookies";
            this.enablefiltercheckBox.UseVisualStyleBackColor = true;
            this.enablefiltercheckBox.CheckedChanged += new System.EventHandler(this.enablefiltercheckBox_CheckedChanged);
            // 
            // cookiecheckgroupBox
            // 
            this.cookiecheckgroupBox.Controls.Add(this.enablefiltercheckBox);
            this.cookiecheckgroupBox.Dock = System.Windows.Forms.DockStyle.Fill;
            this.cookiecheckgroupBox.Location = new System.Drawing.Point(0, 0);
            this.cookiecheckgroupBox.Name = "cookiecheckgroupBox";
            this.cookiecheckgroupBox.Size = new System.Drawing.Size(472, 178);
            this.cookiecheckgroupBox.TabIndex = 0;
            this.cookiecheckgroupBox.TabStop = false;
            this.cookiecheckgroupBox.Text = "Check Configuration";
            // 
            // EnableCheckConfigPanel
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.cookiecheckgroupBox);
            this.Name = "EnableCheckConfigPanel";
            this.Size = new System.Drawing.Size(472, 178);
            this.cookiecheckgroupBox.ResumeLayout(false);
            this.cookiecheckgroupBox.PerformLayout();
            this.ResumeLayout(false);

        }

        #endregion

        public System.Windows.Forms.CheckBox enablefiltercheckBox;
        private System.Windows.Forms.GroupBox cookiecheckgroupBox;
        private System.Windows.Forms.ToolTip toolTipEnableConfigUI;
    }
}
