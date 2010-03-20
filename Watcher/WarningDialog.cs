using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;

namespace CasabaSecurity.Web.Watcher
{
    public partial class WarningDialog : Form
    {
        public WarningDialog()
        {
            InitializeComponent();
            this.pictureBox1.Image = SystemIcons.Warning.ToBitmap();
            base.Text = "Watcher";
        }

        public new String Text
        {
            get { return this.richTextBox1.Text; }
            set { this.richTextBox1.Text = value; }
        }
    }
}
