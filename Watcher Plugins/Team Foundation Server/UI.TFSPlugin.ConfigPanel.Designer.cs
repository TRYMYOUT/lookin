namespace CasabaSecurity.Web.Watcher.TeamFoundation
{
    partial class TeamFoundationPluginConfigPanel
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
            this.tfsoutputgroupBox = new System.Windows.Forms.GroupBox();
            this.editbutton = new System.Windows.Forms.Button();
            this.projectnametextBox = new System.Windows.Forms.TextBox();
            this.projectnamelabel = new System.Windows.Forms.Label();
            this.servernamelabel = new System.Windows.Forms.Label();
            this.servernametextBox = new System.Windows.Forms.TextBox();
            this.tfsoutputgroupBox.SuspendLayout();
            this.SuspendLayout();
            // 
            // tfsoutputgroupBox
            // 
            this.tfsoutputgroupBox.Controls.Add(this.editbutton);
            this.tfsoutputgroupBox.Controls.Add(this.projectnametextBox);
            this.tfsoutputgroupBox.Controls.Add(this.projectnamelabel);
            this.tfsoutputgroupBox.Controls.Add(this.servernamelabel);
            this.tfsoutputgroupBox.Controls.Add(this.servernametextBox);
            this.tfsoutputgroupBox.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tfsoutputgroupBox.Location = new System.Drawing.Point(0, 0);
            this.tfsoutputgroupBox.Name = "tfsoutputgroupBox";
            this.tfsoutputgroupBox.Size = new System.Drawing.Size(479, 102);
            this.tfsoutputgroupBox.TabIndex = 0;
            this.tfsoutputgroupBox.TabStop = false;
            this.tfsoutputgroupBox.Text = "Team Foundation Server";
            // 
            // editbutton
            // 
            this.editbutton.Location = new System.Drawing.Point(321, 29);
            this.editbutton.Name = "editbutton";
            this.editbutton.Size = new System.Drawing.Size(127, 46);
            this.editbutton.TabIndex = 4;
            this.editbutton.Text = "Edit Field Mapping";
            this.editbutton.UseVisualStyleBackColor = true;
            this.editbutton.Click += new System.EventHandler(this.editbutton_Click);
            // 
            // projectnametextBox
            // 
            this.projectnametextBox.Location = new System.Drawing.Point(95, 55);
            this.projectnametextBox.Name = "projectnametextBox";
            this.projectnametextBox.Size = new System.Drawing.Size(126, 20);
            this.projectnametextBox.TabIndex = 3;
            this.projectnametextBox.TextChanged += new System.EventHandler(this.projectnametextBox_TextChanged);
            // 
            // projectnamelabel
            // 
            this.projectnamelabel.AutoSize = true;
            this.projectnamelabel.Location = new System.Drawing.Point(11, 58);
            this.projectnamelabel.Name = "projectnamelabel";
            this.projectnamelabel.Size = new System.Drawing.Size(74, 13);
            this.projectnamelabel.TabIndex = 2;
            this.projectnamelabel.Text = "Project Name:";
            // 
            // servernamelabel
            // 
            this.servernamelabel.AutoSize = true;
            this.servernamelabel.Location = new System.Drawing.Point(11, 32);
            this.servernamelabel.Name = "servernamelabel";
            this.servernamelabel.Size = new System.Drawing.Size(72, 13);
            this.servernamelabel.TabIndex = 1;
            this.servernamelabel.Text = "Server Name:";
            // 
            // servernametextBox
            // 
            this.servernametextBox.Location = new System.Drawing.Point(95, 29);
            this.servernametextBox.Name = "servernametextBox";
            this.servernametextBox.Size = new System.Drawing.Size(126, 20);
            this.servernametextBox.TabIndex = 0;
            this.servernametextBox.TextChanged += new System.EventHandler(this.servernametextBox_TextChanged);
            // 
            // TFSConfigUI
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.tfsoutputgroupBox);
            this.Name = "TFSConfigUI";
            this.Size = new System.Drawing.Size(479, 102);
            this.tfsoutputgroupBox.ResumeLayout(false);
            this.tfsoutputgroupBox.PerformLayout();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.GroupBox tfsoutputgroupBox;
        private System.Windows.Forms.TextBox projectnametextBox;
        private System.Windows.Forms.Label projectnamelabel;
        private System.Windows.Forms.Label servernamelabel;
        private System.Windows.Forms.TextBox servernametextBox;
        private System.Windows.Forms.Button editbutton;
    }
}
