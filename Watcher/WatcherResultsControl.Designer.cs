// WATCHER
//
// WatcherConfig.Designer.cs
// 
//
// Copyright (c) 2009 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.IO;
using System.Collections;
using System.Xml;
using System.Drawing;
using System.Net;
using System.Windows.Forms;
using System.Threading;
using System.Text;
using System.Text.RegularExpressions;
using System.Reflection;
using System.Collections.Generic;
using Fiddler;
using System.Runtime.InteropServices;

namespace CasabaSecurity.Web.Watcher
{
    public enum ListViewExtendedStyles
    {
        /// <summary>
        /// LVS_EX_GRIDLINES
        /// </summary>
        GridLines = 0x00000001,
        /// <summary>
        /// LVS_EX_SUBITEMIMAGES
        /// </summary>
        SubItemImages = 0x00000002,
        /// <summary>
        /// LVS_EX_CHECKBOXES
        /// </summary>
        CheckBoxes = 0x00000004,
        /// <summary>
        /// LVS_EX_TRACKSELECT
        /// </summary>
        TrackSelect = 0x00000008,
        /// <summary>
        /// LVS_EX_HEADERDRAGDROP
        /// </summary>
        HeaderDragDrop = 0x00000010,
        /// <summary>
        /// LVS_EX_FULLROWSELECT
        /// </summary>
        FullRowSelect = 0x00000020,
        /// <summary>
        /// LVS_EX_ONECLICKACTIVATE
        /// </summary>
        OneClickActivate = 0x00000040,
        /// <summary>
        /// LVS_EX_TWOCLICKACTIVATE
        /// </summary>
        TwoClickActivate = 0x00000080,
        /// <summary>
        /// LVS_EX_FLATSB
        /// </summary>
        FlatsB = 0x00000100,
        /// <summary>
        /// LVS_EX_REGIONAL
        /// </summary>
        Regional = 0x00000200,
        /// <summary>
        /// LVS_EX_INFOTIP
        /// </summary>
        InfoTip = 0x00000400,
        /// <summary>
        /// LVS_EX_UNDERLINEHOT
        /// </summary>
        UnderlineHot = 0x00000800,
        /// <summary>
        /// LVS_EX_UNDERLINECOLD
        /// </summary>
        UnderlineCold = 0x00001000,
        /// <summary>
        /// LVS_EX_MULTIWORKAREAS
        /// </summary>
        MultilWorkAreas = 0x00002000,
        /// <summary>
        /// LVS_EX_LABELTIP
        /// </summary>
        LabelTip = 0x00004000,
        /// <summary>
        /// LVS_EX_BORDERSELECT
        /// </summary>
        BorderSelect = 0x00008000,
        /// <summary>
        /// LVS_EX_DOUBLEBUFFER
        /// </summary>
        DoubleBuffer = 0x00010000,
        /// <summary>
        /// LVS_EX_HIDELABELS
        /// </summary>
        HideLabels = 0x00020000,
        /// <summary>
        /// LVS_EX_SINGLEROW
        /// </summary>
        SingleRow = 0x00040000,
        /// <summary>
        /// LVS_EX_SNAPTOGRID
        /// </summary>
        SnapToGrid = 0x00080000,
        /// <summary>
        /// LVS_EX_SIMPLESELECT
        /// </summary>
        SimpleSelect = 0x00100000
    }

    public enum ListViewMessages
    {
        First = 0x1000,
        SetExtendedStyle = (First + 54),
        GetExtendedStyle = (First + 55),
    }

    /// <summary>
    /// Contains helper methods to change extended styles on ListView, including enabling double buffering.
    /// Based on Giovanni Montrone's article on <see cref="http://www.codeproject.com/KB/list/listviewxp.aspx"/>
    /// </summary>
    public class ListViewHelper
    {
        private ListViewHelper()
        {
        }

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern int SendMessage(IntPtr handle, int messg, int wparam, int lparam);

        public static void SetExtendedStyle(Control control, ListViewExtendedStyles exStyle)
        {
            ListViewExtendedStyles styles;
            styles = (ListViewExtendedStyles)SendMessage(control.Handle, (int)ListViewMessages.GetExtendedStyle, 0, 0);
            styles |= exStyle;
            SendMessage(control.Handle, (int)ListViewMessages.SetExtendedStyle, 0, (int)styles);
        }

        public static void EnableDoubleBuffer(Control control)
        {
            ListViewExtendedStyles styles;
            // read current style
            styles = (ListViewExtendedStyles)SendMessage(control.Handle, (int)ListViewMessages.GetExtendedStyle, 0, 0);
            // enable double buffer and border select
            styles |= ListViewExtendedStyles.DoubleBuffer | ListViewExtendedStyles.BorderSelect;
            // write new style
            SendMessage(control.Handle, (int)ListViewMessages.SetExtendedStyle, 0, (int)styles);
        }

        public static void DisableDoubleBuffer(Control control)
        {
            ListViewExtendedStyles styles;
            // read current style
            styles = (ListViewExtendedStyles)SendMessage(control.Handle, (int)ListViewMessages.GetExtendedStyle, 0, 0);
            // disable double buffer and border select
            styles -= styles & ListViewExtendedStyles.DoubleBuffer;
            styles -= styles & ListViewExtendedStyles.BorderSelect;
            // write new style
            SendMessage(control.Handle, (int)ListViewMessages.SetExtendedStyle, 0, (int)styles);
        }
    }
    
    partial class WatcherResultsControl : UserControl
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(WatcherResultsControl));
            this.alertGroupBox = new System.Windows.Forms.GroupBox();
            this.linkLabel = new System.Windows.Forms.LinkLabel();
            this.alertListView = new System.Windows.Forms.ListView();
            this.severityColumnHeader = new System.Windows.Forms.ColumnHeader();
            this.sessionIdColumnHeader = new System.Windows.Forms.ColumnHeader();
            this.typeColumnHeader = new System.Windows.Forms.ColumnHeader();
            this.urlColumnHeader = new System.Windows.Forms.ColumnHeader();
            this.filterpanel = new System.Windows.Forms.Panel();
            this.casabapictureBox = new System.Windows.Forms.PictureBox();
            this.label1 = new System.Windows.Forms.Label();
            this.informationalcountlabel = new System.Windows.Forms.Label();
            this.lowcountlabel = new System.Windows.Forms.Label();
            this.mediumcountlabel = new System.Windows.Forms.Label();
            this.highcountlabel = new System.Windows.Forms.Label();
            this.noiselabel = new System.Windows.Forms.Label();
            this.noisereductioncomboBox = new System.Windows.Forms.ComboBox();
            this.listviewbuttonpanel = new System.Windows.Forms.Panel();
            this.autoscrollcheckBox = new System.Windows.Forms.CheckBox();
            this.FileSaveButton = new System.Windows.Forms.Button();
            this.btnClearResults = new System.Windows.Forms.Button();
            this.resultPanel = new System.Windows.Forms.Panel();
            this.alertTextBox = new System.Windows.Forms.TextBox();
            this.lowerpanel = new System.Windows.Forms.Panel();
            this.splitContainer = new System.Windows.Forms.SplitContainer();
            this.alertGroupBox.SuspendLayout();
            this.filterpanel.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.casabapictureBox)).BeginInit();
            this.listviewbuttonpanel.SuspendLayout();
            this.resultPanel.SuspendLayout();
            this.lowerpanel.SuspendLayout();
            this.splitContainer.Panel1.SuspendLayout();
            this.splitContainer.Panel2.SuspendLayout();
            this.splitContainer.SuspendLayout();
            this.SuspendLayout();
            // 
            // alertGroupBox
            // 
            this.alertGroupBox.AutoSize = true;
            this.alertGroupBox.BackColor = System.Drawing.Color.LightGray;
            this.alertGroupBox.Controls.Add(this.linkLabel);
            this.alertGroupBox.Controls.Add(this.alertListView);
            this.alertGroupBox.Controls.Add(this.filterpanel);
            this.alertGroupBox.Controls.Add(this.listviewbuttonpanel);
            this.alertGroupBox.Dock = System.Windows.Forms.DockStyle.Fill;
            this.alertGroupBox.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.alertGroupBox.Location = new System.Drawing.Point(0, 0);
            this.alertGroupBox.Name = "alertGroupBox";
            this.alertGroupBox.Size = new System.Drawing.Size(851, 298);
            this.alertGroupBox.TabIndex = 0;
            this.alertGroupBox.TabStop = false;
            this.alertGroupBox.Text = "Watcher by ";
            // 
            // linkLabel
            // 
            this.linkLabel.AutoSize = true;
            this.linkLabel.Location = new System.Drawing.Point(77, 0);
            this.linkLabel.Margin = new System.Windows.Forms.Padding(6, 0, 6, 0);
            this.linkLabel.Name = "linkLabel";
            this.linkLabel.Size = new System.Drawing.Size(99, 13);
            this.linkLabel.TabIndex = 0;
            this.linkLabel.TabStop = true;
            this.linkLabel.Text = "Casaba Security";
            this.linkLabel.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.linkLabel_LinkClicked);
            // 
            // alertListView
            // 
            this.alertListView.Activation = System.Windows.Forms.ItemActivation.OneClick;
            this.alertListView.AllowColumnReorder = true;
            this.alertListView.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.severityColumnHeader,
            this.sessionIdColumnHeader,
            this.typeColumnHeader,
            this.urlColumnHeader});
            this.alertListView.Dock = System.Windows.Forms.DockStyle.Fill;
            this.alertListView.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.alertListView.FullRowSelect = true;
            this.alertListView.GridLines = true;
            this.alertListView.HideSelection = false;
            this.alertListView.Location = new System.Drawing.Point(3, 65);
            this.alertListView.Name = "alertListView";
            this.alertListView.Size = new System.Drawing.Size(845, 181);
            this.alertListView.TabIndex = 2;
            this.alertListView.UseCompatibleStateImageBehavior = false;
            this.alertListView.View = System.Windows.Forms.View.Details;
            this.alertListView.SelectedIndexChanged += new System.EventHandler(this.alertListView_SelectedIndexChanged);
            this.alertListView.DoubleClick += new System.EventHandler(this.alertListViewDoubleClick);
            this.alertListView.ColumnClick += new System.Windows.Forms.ColumnClickEventHandler(this.alertListView_ColumnClick);
            this.alertListView.KeyDown += new System.Windows.Forms.KeyEventHandler(this.copyToClipboard);
            // 
            // severityColumnHeader
            // 
            this.severityColumnHeader.Text = "Severity";
            this.severityColumnHeader.Width = 100;
            // 
            // sessionIdColumnHeader
            // 
            this.sessionIdColumnHeader.Text = "Session ID";
            this.sessionIdColumnHeader.Width = 125;
            // 
            // typeColumnHeader
            // 
            this.typeColumnHeader.Text = "Type";
            this.typeColumnHeader.Width = 200;
            // 
            // urlColumnHeader
            // 
            this.urlColumnHeader.Text = "URL";
            this.urlColumnHeader.Width = 420;
            // 
            // filterpanel
            // 
            this.filterpanel.AutoSize = true;
            this.filterpanel.Controls.Add(this.casabapictureBox);
            this.filterpanel.Controls.Add(this.label1);
            this.filterpanel.Controls.Add(this.informationalcountlabel);
            this.filterpanel.Controls.Add(this.lowcountlabel);
            this.filterpanel.Controls.Add(this.mediumcountlabel);
            this.filterpanel.Controls.Add(this.highcountlabel);
            this.filterpanel.Controls.Add(this.noiselabel);
            this.filterpanel.Controls.Add(this.noisereductioncomboBox);
            this.filterpanel.Dock = System.Windows.Forms.DockStyle.Top;
            this.filterpanel.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.filterpanel.Location = new System.Drawing.Point(3, 16);
            this.filterpanel.Margin = new System.Windows.Forms.Padding(0);
            this.filterpanel.Name = "filterpanel";
            this.filterpanel.Size = new System.Drawing.Size(845, 49);
            this.filterpanel.TabIndex = 1;
            // 
            // casabapictureBox
            // 
            this.casabapictureBox.Dock = System.Windows.Forms.DockStyle.Left;
            this.casabapictureBox.Image = ((System.Drawing.Image)(resources.GetObject("casabapictureBox.Image")));
            this.casabapictureBox.Location = new System.Drawing.Point(0, 0);
            this.casabapictureBox.Margin = new System.Windows.Forms.Padding(3, 3, 25, 3);
            this.casabapictureBox.Name = "casabapictureBox";
            this.casabapictureBox.Size = new System.Drawing.Size(50, 49);
            this.casabapictureBox.SizeMode = System.Windows.Forms.PictureBoxSizeMode.CenterImage;
            this.casabapictureBox.TabIndex = 10;
            this.casabapictureBox.TabStop = false;
            this.casabapictureBox.Visible = false;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(355, 4);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(155, 13);
            this.label1.TabIndex = 2;
            this.label1.Text = "Totals (Alerts, Individual Issues)";
            // 
            // informationalcountlabel
            // 
            this.informationalcountlabel.AutoSize = true;
            this.informationalcountlabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.informationalcountlabel.ForeColor = System.Drawing.Color.Green;
            this.informationalcountlabel.Location = new System.Drawing.Point(522, 28);
            this.informationalcountlabel.Name = "informationalcountlabel";
            this.informationalcountlabel.Size = new System.Drawing.Size(70, 13);
            this.informationalcountlabel.TabIndex = 6;
            this.informationalcountlabel.Text = "Informational:";
            this.informationalcountlabel.Click += new System.EventHandler(this.informationalcountlabel_Click);
            // 
            // lowcountlabel
            // 
            this.lowcountlabel.AutoSize = true;
            this.lowcountlabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lowcountlabel.ForeColor = System.Drawing.Color.Blue;
            this.lowcountlabel.Location = new System.Drawing.Point(451, 28);
            this.lowcountlabel.Name = "lowcountlabel";
            this.lowcountlabel.Size = new System.Drawing.Size(30, 13);
            this.lowcountlabel.TabIndex = 5;
            this.lowcountlabel.Text = "Low:";
            this.lowcountlabel.Click += new System.EventHandler(this.lowcountlabel_Click);
            // 
            // mediumcountlabel
            // 
            this.mediumcountlabel.AutoSize = true;
            this.mediumcountlabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.mediumcountlabel.ForeColor = System.Drawing.Color.Orange;
            this.mediumcountlabel.Location = new System.Drawing.Point(365, 28);
            this.mediumcountlabel.Name = "mediumcountlabel";
            this.mediumcountlabel.Size = new System.Drawing.Size(47, 13);
            this.mediumcountlabel.TabIndex = 4;
            this.mediumcountlabel.Text = "Medium:";
            this.mediumcountlabel.Click += new System.EventHandler(this.mediumcountlabel_Click);
            // 
            // highcountlabel
            // 
            this.highcountlabel.AutoSize = true;
            this.highcountlabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.highcountlabel.ForeColor = System.Drawing.Color.Red;
            this.highcountlabel.Location = new System.Drawing.Point(294, 28);
            this.highcountlabel.Name = "highcountlabel";
            this.highcountlabel.Size = new System.Drawing.Size(35, 13);
            this.highcountlabel.TabIndex = 3;
            this.highcountlabel.Text = "High: ";
            this.highcountlabel.Click += new System.EventHandler(this.highcountlabel_Click);
            // 
            // noiselabel
            // 
            this.noiselabel.AutoSize = true;
            this.noiselabel.Location = new System.Drawing.Point(67, 28);
            this.noiselabel.Name = "noiselabel";
            this.noiselabel.Size = new System.Drawing.Size(59, 13);
            this.noiselabel.TabIndex = 0;
            this.noiselabel.Text = " Alert Filter:";
            // 
            // noisereductioncomboBox
            // 
            this.noisereductioncomboBox.DisplayMember = "Informational";
            this.noisereductioncomboBox.FormattingEnabled = true;
            this.noisereductioncomboBox.Items.AddRange(new object[] {
            "Informational",
            "Low",
            "Medium",
            "High"});
            this.noisereductioncomboBox.Location = new System.Drawing.Point(133, 25);
            this.noisereductioncomboBox.Name = "noisereductioncomboBox";
            this.noisereductioncomboBox.Size = new System.Drawing.Size(121, 21);
            this.noisereductioncomboBox.TabIndex = 1;
            this.noisereductioncomboBox.ValueMember = "Informational";
            this.noisereductioncomboBox.SelectedIndexChanged += new System.EventHandler(this.comboBox1_SelectedIndexChanged);
            // 
            // listviewbuttonpanel
            // 
            this.listviewbuttonpanel.Controls.Add(this.autoscrollcheckBox);
            this.listviewbuttonpanel.Controls.Add(this.FileSaveButton);
            this.listviewbuttonpanel.Controls.Add(this.btnClearResults);
            this.listviewbuttonpanel.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.listviewbuttonpanel.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.listviewbuttonpanel.Location = new System.Drawing.Point(3, 246);
            this.listviewbuttonpanel.Name = "listviewbuttonpanel";
            this.listviewbuttonpanel.Size = new System.Drawing.Size(845, 49);
            this.listviewbuttonpanel.TabIndex = 3;
            // 
            // autoscrollcheckBox
            // 
            this.autoscrollcheckBox.AutoSize = true;
            this.autoscrollcheckBox.Location = new System.Drawing.Point(537, 18);
            this.autoscrollcheckBox.Name = "autoscrollcheckBox";
            this.autoscrollcheckBox.Size = new System.Drawing.Size(74, 17);
            this.autoscrollcheckBox.TabIndex = 2;
            this.autoscrollcheckBox.Text = "AutoScroll";
            this.autoscrollcheckBox.UseVisualStyleBackColor = true;
            this.autoscrollcheckBox.CheckedChanged += new System.EventHandler(this.autoscrollcheckBox_CheckedChanged);
            // 
            // FileSaveButton
            // 
            this.FileSaveButton.Location = new System.Drawing.Point(352, 11);
            this.FileSaveButton.Name = "FileSaveButton";
            this.FileSaveButton.Size = new System.Drawing.Size(130, 29);
            this.FileSaveButton.TabIndex = 1;
            this.FileSaveButton.Text = "Export to XML";
            this.FileSaveButton.UseVisualStyleBackColor = true;
            this.FileSaveButton.Click += new System.EventHandler(this.FileSaveButton_Click);
            // 
            // btnClearResults
            // 
            this.btnClearResults.Location = new System.Drawing.Point(13, 11);
            this.btnClearResults.Name = "btnClearResults";
            this.btnClearResults.Size = new System.Drawing.Size(299, 29);
            this.btnClearResults.TabIndex = 0;
            this.btnClearResults.Text = "Clear Selected Results (All results if none selected)";
            this.btnClearResults.UseVisualStyleBackColor = true;
            this.btnClearResults.Click += new System.EventHandler(this.btnClearNoisyChecks_Click);
            // 
            // resultPanel
            // 
            this.resultPanel.Controls.Add(this.alertTextBox);
            this.resultPanel.Dock = System.Windows.Forms.DockStyle.Fill;
            this.resultPanel.Location = new System.Drawing.Point(0, 0);
            this.resultPanel.Margin = new System.Windows.Forms.Padding(0);
            this.resultPanel.Name = "resultPanel";
            this.resultPanel.Size = new System.Drawing.Size(851, 351);
            this.resultPanel.TabIndex = 3;
            // 
            // alertTextBox
            // 
            this.alertTextBox.BackColor = System.Drawing.SystemColors.GradientInactiveCaption;
            this.alertTextBox.Dock = System.Windows.Forms.DockStyle.Fill;
            this.alertTextBox.Location = new System.Drawing.Point(0, 0);
            this.alertTextBox.Multiline = true;
            this.alertTextBox.Name = "alertTextBox";
            this.alertTextBox.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.alertTextBox.Size = new System.Drawing.Size(851, 351);
            this.alertTextBox.TabIndex = 0;
            this.alertTextBox.KeyDown += new System.Windows.Forms.KeyEventHandler(this.resultcopyToClipboard);
            // 
            // lowerpanel
            // 
            this.lowerpanel.AutoSize = true;
            this.lowerpanel.Controls.Add(this.splitContainer);
            this.lowerpanel.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lowerpanel.Location = new System.Drawing.Point(0, 0);
            this.lowerpanel.Name = "lowerpanel";
            this.lowerpanel.Size = new System.Drawing.Size(851, 653);
            this.lowerpanel.TabIndex = 4;
            // 
            // splitContainer
            // 
            this.splitContainer.Dock = System.Windows.Forms.DockStyle.Fill;
            this.splitContainer.Location = new System.Drawing.Point(0, 0);
            this.splitContainer.Name = "splitContainer";
            this.splitContainer.Orientation = System.Windows.Forms.Orientation.Horizontal;
            // 
            // splitContainer.Panel1
            // 
            this.splitContainer.Panel1.Controls.Add(this.alertGroupBox);
            // 
            // splitContainer.Panel2
            // 
            this.splitContainer.Panel2.Controls.Add(this.resultPanel);
            this.splitContainer.Size = new System.Drawing.Size(851, 653);
            this.splitContainer.SplitterDistance = 298;
            this.splitContainer.TabIndex = 0;
            // 
            // WatcherResultsControl
            // 
            this.Controls.Add(this.lowerpanel);
            this.Margin = new System.Windows.Forms.Padding(0);
            this.Name = "WatcherResultsControl";
            this.Size = new System.Drawing.Size(851, 653);
            this.alertGroupBox.ResumeLayout(false);
            this.alertGroupBox.PerformLayout();
            this.filterpanel.ResumeLayout(false);
            this.filterpanel.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.casabapictureBox)).EndInit();
            this.listviewbuttonpanel.ResumeLayout(false);
            this.listviewbuttonpanel.PerformLayout();
            this.resultPanel.ResumeLayout(false);
            this.resultPanel.PerformLayout();
            this.lowerpanel.ResumeLayout(false);
            this.splitContainer.Panel1.ResumeLayout(false);
            this.splitContainer.Panel1.PerformLayout();
            this.splitContainer.Panel2.ResumeLayout(false);
            this.splitContainer.ResumeLayout(false);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        public GroupBox alertGroupBox;
        public ListView alertListView;
        public ColumnHeader sessionIdColumnHeader;
        public ColumnHeader severityColumnHeader;
        public ColumnHeader typeColumnHeader;
        public ColumnHeader urlColumnHeader;
        public Panel resultPanel;
        public Button btnClearResults;
        public Button FileSaveButton;
        private TextBox alertTextBox;
        private Panel lowerpanel;
        private SplitContainer splitContainer;
        private Panel listviewbuttonpanel;
        public ComboBox noisereductioncomboBox;
        private Panel filterpanel;
        private Label noiselabel;
        private LinkLabel linkLabel;
        private Label highcountlabel;
        private Label informationalcountlabel;
        private Label lowcountlabel;
        private Label mediumcountlabel;
        private Label label1;
        private PictureBox casabapictureBox;
        private CheckBox autoscrollcheckBox;
       
        public class AlertListViewItem : ListViewItem
        {
            #region Fields
            private Int32 _id;
            private WatcherResultSeverity _severity;
            private String _url;
            private String _name;
            private String _description;
            private Int32 _count;
            #endregion

            #region Ctor(s)
            public AlertListViewItem(WatcherResultSeverity severity, Int32 id, String name, String url, String description, int count)
            {
                _id = id;
                _severity = severity;
                _url = url;
                _name = name;
                _description = description;
                _count = count;

                // Set the item text to the canonical version of the WatcherResutlSeverity
                this.Text = severity.ToString();
            }
            #endregion

            #region Public Properties

            public WatcherResultSeverity Severity
            {
                get { return _severity; }
            }

            public Int32 AlertCount
            {
                get { return _count; }
            }

            public Int32 ID
            {
                get { return _id; }
            }

            public String URL
            {
                get { return _url; }
            }

            public String TypeX
            {
                get { return _name; }
            }

            public String Description
            {
                get { return _description; }
            }

            #endregion

            #region Public Method(s)

            public override String ToString()
            {
                string output = "";
                output = output + Severity.ToString() + "\t"
                        + this.ID + "\t"
                        + this.TypeX + "\t"
                        + this.URL + "\r\n";
                return output;
            }

            public override bool Equals(Object obj)
            {
                AlertListViewItem alvi = null;

                if (obj is AlertListViewItem)
                {
                    alvi = (AlertListViewItem)obj;

                    if (alvi.Severity == this.Severity && alvi.URL == this.URL && alvi.TypeX == this.TypeX && alvi.Description == this.Description)
                    {
                        return (true);
                    }

                    return (false);
                }

                return base.Equals(obj);
            }

            public override int GetHashCode()
            {
                return base.GetHashCode();
            }

            #endregion
        }

        public class AlertListViewColumnSorter : IComparer
        {
            // Specifies the column to be sorted
            private int ColumnToSort;
            
            // Specifies the order in which to sort (i.e. 'Ascending').
            private SortOrder OrderOfSort;
            
            // Case insensitive comparer object
            private CaseInsensitiveComparer ObjectCompare;
            private bool num;
            private bool sev;

            /// <summary>
            /// Class constructor.  Initializes various elements
            /// </summary>
            public AlertListViewColumnSorter()
            {
                // Initialize the column to '0'
                ColumnToSort = 0;

                // Initialize the sort order to 'none'
                OrderOfSort = SortOrder.None;

                // Initialize the CaseInsensitiveComparer object
                ObjectCompare = new CaseInsensitiveComparer();
            }

            /// <summary>
            /// This method is inherited from the IComparer interface.  It compares the two objects passed using a case insensitive comparison.
            /// </summary>
            /// <param name="x">First object to be compared</param>
            /// <param name="y">Second object to be compared</param>
            /// <returns>The result of the comparison. "0" if equal, negative if 'x' is less than 'y' and positive if 'x' is greater than 'y'</returns>
            public int Compare(object x, object y)
            {
                int compareResult;
                ListViewItem listviewX, listviewY;

                // Cast the objects to be compared to ListViewItem objects
                listviewX = (ListViewItem)x;
                listviewY = (ListViewItem)y;

                if (num == false)
                {
                    if (sev == true)
                    {
                        String a = listviewX.SubItems[ColumnToSort].Text;
                        String b = listviewY.SubItems[ColumnToSort].Text;
                        //TODO: Fix this ugly hack to simplify text sorting for the severity column
                        if (a == "High")
                        {
                            a = "XHigh";
                        }
                        if (b == "High")
                        {
                            b = "XHigh";
                        }
                        // normal string compare
                        compareResult = ObjectCompare.Compare(a, b);
                    }
                    else
                    {
                        compareResult = ObjectCompare.Compare(listviewX.SubItems[ColumnToSort].Text, listviewY.SubItems[ColumnToSort].Text);
                    }
                }
                else
                {
                    int valueX;
                    int valueY;

                    ObjectCompare = new CaseInsensitiveComparer();

                    // natural numeric sort order
                    compareResult = ObjectCompare.Compare((int.TryParse(listviewX.SubItems[ColumnToSort].Text, out valueX) ? valueX : 0), (int.TryParse(listviewY.SubItems[ColumnToSort].Text, out valueY) ? valueY : 0));
                }
                // Calculate correct return value based on object comparison
                if (OrderOfSort == SortOrder.Ascending)
                {
                    // Ascending sort is selected, return normal result of compare operation
                    return compareResult;
                }
                else if (OrderOfSort == SortOrder.Descending)
                {
                    // Descending sort is selected, return negative result of compare operation
                    return (-compareResult);
                }
                else
                {
                    // Return '0' to indicate they are equal
                    return 0;
                }

            }

            /// <summary>
            /// Gets or sets the number of the column to which to apply the sorting operation (Defaults to '0').
            /// </summary>
            public int SortColumn
            {
                set
                {
                    ColumnToSort = value;
                }
                get
                {
                    return ColumnToSort;
                }
            }

            public bool Severity
            {
                set
                {
                    sev = value;
                }
                get
                {
                    return sev;
                }
            }

            public bool Number
            {
                set
                {
                    num = value;
                }
                get
                {
                    return num;
                }
            }

            /// <summary>
            /// Gets or sets the order of sorting to apply (for example, 'Ascending' or 'Descending').
            /// </summary>
            public SortOrder Order
            {
                set
                {
                    OrderOfSort = value;
                }
                get
                {
                    return OrderOfSort;
                }
            }

        }
    }
}