// WATCHER
//
// WatcherResultsControl.Designer.cs
//
// Copyright (c) 2010 Casaba Security, LLC
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
    // TODO: Move this elsewhere
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

    // TODO: Make this internal.  Checks should use ResultsManager.
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
#if false
        {
            this.resultPanel = new System.Windows.Forms.Panel();
            this.alertTextBox = new System.Windows.Forms.TextBox();
            this.lowerpanel = new System.Windows.Forms.Panel();
            this.splitContainer = new System.Windows.Forms.SplitContainer();
            this.alertListView = new System.Windows.Forms.ListView();
            this.severityColumnHeader = new System.Windows.Forms.ColumnHeader();
            this.sessionIdColumnHeader = new System.Windows.Forms.ColumnHeader();
            this.typeColumnHeader = new System.Windows.Forms.ColumnHeader();
            this.urlColumnHeader = new System.Windows.Forms.ColumnHeader();
            this.buttonpanel = new System.Windows.Forms.Panel();
            this.btnClearResults = new System.Windows.Forms.Button();
            this.FileSaveButton = new System.Windows.Forms.Button();
            this.autoscrollcheckBox = new System.Windows.Forms.CheckBox();
            this.filterpanel = new System.Windows.Forms.Panel();
            this.label1 = new System.Windows.Forms.Label();
            this.informationalcountlabel = new System.Windows.Forms.Label();
            this.noiselabel = new System.Windows.Forms.Label();
            this.lowcountlabel = new System.Windows.Forms.Label();
            this.noisereductioncomboBox = new System.Windows.Forms.ComboBox();
            this.mediumcountlabel = new System.Windows.Forms.Label();
            this.highcountlabel = new System.Windows.Forms.Label();
            this.resultPanel.SuspendLayout();
            this.lowerpanel.SuspendLayout();
            this.splitContainer.Panel1.SuspendLayout();
            this.splitContainer.Panel2.SuspendLayout();
            this.splitContainer.SuspendLayout();
            this.buttonpanel.SuspendLayout();
            this.filterpanel.SuspendLayout();
            this.SuspendLayout();
            // 
            // resultPanel
            // 
            this.resultPanel.Controls.Add(this.alertTextBox);
            this.resultPanel.Dock = System.Windows.Forms.DockStyle.Fill;
            this.resultPanel.Location = new System.Drawing.Point(0, 0);
            this.resultPanel.Margin = new System.Windows.Forms.Padding(0);
            this.resultPanel.Name = "resultPanel";
            this.resultPanel.Size = new System.Drawing.Size(849, 300);
            this.resultPanel.TabIndex = 3;
            // 
            // alertTextBox
            // 
            this.alertTextBox.BackColor = System.Drawing.SystemColors.GradientInactiveCaption;
            this.alertTextBox.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.alertTextBox.Dock = System.Windows.Forms.DockStyle.Fill;
            this.alertTextBox.Location = new System.Drawing.Point(0, 0);
            this.alertTextBox.Margin = new System.Windows.Forms.Padding(0);
            this.alertTextBox.Multiline = true;
            this.alertTextBox.Name = "alertTextBox";
            this.alertTextBox.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.alertTextBox.Size = new System.Drawing.Size(849, 300);
            this.alertTextBox.TabIndex = 0;
            this.alertTextBox.KeyDown += new System.Windows.Forms.KeyEventHandler(this.resultcopyToClipboard);
            // 
            // lowerpanel
            // 
            this.lowerpanel.AutoSize = true;
            this.lowerpanel.BackColor = System.Drawing.SystemColors.Window;
            this.lowerpanel.Controls.Add(this.splitContainer);
            this.lowerpanel.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lowerpanel.Location = new System.Drawing.Point(0, 0);
            this.lowerpanel.Margin = new System.Windows.Forms.Padding(0);
            this.lowerpanel.Name = "lowerpanel";
            this.lowerpanel.Size = new System.Drawing.Size(851, 653);
            this.lowerpanel.TabIndex = 4;
            // 
            // splitContainer
            // 
            this.splitContainer.BackColor = System.Drawing.SystemColors.Window;
            this.splitContainer.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.splitContainer.Dock = System.Windows.Forms.DockStyle.Fill;
            this.splitContainer.Location = new System.Drawing.Point(0, 0);
            this.splitContainer.Name = "splitContainer";
            this.splitContainer.Orientation = System.Windows.Forms.Orientation.Horizontal;
            // 
            // splitContainer.Panel1
            // 
            this.splitContainer.Panel1.Controls.Add(this.alertListView);
            this.splitContainer.Panel1.Controls.Add(this.buttonpanel);
            this.splitContainer.Panel1.Controls.Add(this.filterpanel);
            this.splitContainer.Panel1.Paint += new System.Windows.Forms.PaintEventHandler(this.splitContainer_Panel1_Paint);
            // 
            // splitContainer.Panel2
            // 
            this.splitContainer.Panel2.Controls.Add(this.resultPanel);
            this.splitContainer.Size = new System.Drawing.Size(851, 653);
            this.splitContainer.SplitterDistance = 347;
            this.splitContainer.TabIndex = 0;
            // 
            // alertListView
            // 
            this.alertListView.Activation = System.Windows.Forms.ItemActivation.OneClick;
            this.alertListView.AllowColumnReorder = true;
            this.alertListView.BackColor = System.Drawing.SystemColors.ControlLightLight;
            this.alertListView.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
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
            this.alertListView.Location = new System.Drawing.Point(0, 42);
            this.alertListView.Margin = new System.Windows.Forms.Padding(0);
            this.alertListView.Name = "alertListView";
            this.alertListView.Size = new System.Drawing.Size(849, 261);
            this.alertListView.TabIndex = 7;
            this.alertListView.UseCompatibleStateImageBehavior = false;
            this.alertListView.View = System.Windows.Forms.View.Details;
            this.alertListView.SelectedIndexChanged += new System.EventHandler(this.alertListView_SelectedIndexChanged);
            this.alertListView.DoubleClick += new System.EventHandler(this.alertListViewDoubleClick);
            this.alertListView.ColumnClick += new System.Windows.Forms.ColumnClickEventHandler(this.alertListView_ColumnClick);
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
            // buttonpanel
            // 
            this.buttonpanel.BackColor = System.Drawing.SystemColors.Window;
            this.buttonpanel.Controls.Add(this.btnClearResults);
            this.buttonpanel.Controls.Add(this.FileSaveButton);
            this.buttonpanel.Controls.Add(this.autoscrollcheckBox);
            this.buttonpanel.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.buttonpanel.Location = new System.Drawing.Point(0, 303);
            this.buttonpanel.Margin = new System.Windows.Forms.Padding(0);
            this.buttonpanel.Name = "buttonpanel";
            this.buttonpanel.Size = new System.Drawing.Size(849, 42);
            this.buttonpanel.TabIndex = 11;
            // 
            // btnClearResults
            // 
            this.btnClearResults.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.btnClearResults.Location = new System.Drawing.Point(3, 5);
            this.btnClearResults.Name = "btnClearResults";
            this.btnClearResults.Size = new System.Drawing.Size(299, 29);
            this.btnClearResults.TabIndex = 8;
            this.btnClearResults.Text = "Clear Selected Results (All results if none selected)";
            this.btnClearResults.UseVisualStyleBackColor = true;
            this.btnClearResults.Click += new System.EventHandler(this.btnClearResults_Click);
            // 
            // FileSaveButton
            // 
            this.FileSaveButton.Location = new System.Drawing.Point(308, 5);
            this.FileSaveButton.Name = "FileSaveButton";
            this.FileSaveButton.Size = new System.Drawing.Size(130, 29);
            this.FileSaveButton.TabIndex = 9;
            this.FileSaveButton.Text = "Export to XML";
            this.FileSaveButton.UseVisualStyleBackColor = true;
            this.FileSaveButton.Click += new System.EventHandler(this.FileSaveButton_Click);
            // 
            // autoscrollcheckBox
            // 
            this.autoscrollcheckBox.AutoSize = true;
            this.autoscrollcheckBox.Location = new System.Drawing.Point(772, 12);
            this.autoscrollcheckBox.Name = "autoscrollcheckBox";
            this.autoscrollcheckBox.Size = new System.Drawing.Size(74, 17);
            this.autoscrollcheckBox.TabIndex = 10;
            this.autoscrollcheckBox.Text = "AutoScroll";
            this.autoscrollcheckBox.UseVisualStyleBackColor = true;
            this.autoscrollcheckBox.CheckedChanged += new System.EventHandler(this.autoscrollcheckBox_CheckedChanged);
            // 
            // filterpanel
            // 
            this.filterpanel.BackColor = System.Drawing.SystemColors.Window;
            this.filterpanel.Controls.Add(this.label1);
            this.filterpanel.Controls.Add(this.informationalcountlabel);
            this.filterpanel.Controls.Add(this.noiselabel);
            this.filterpanel.Controls.Add(this.lowcountlabel);
            this.filterpanel.Controls.Add(this.noisereductioncomboBox);
            this.filterpanel.Controls.Add(this.mediumcountlabel);
            this.filterpanel.Controls.Add(this.highcountlabel);
            this.filterpanel.Dock = System.Windows.Forms.DockStyle.Top;
            this.filterpanel.Location = new System.Drawing.Point(0, 0);
            this.filterpanel.Name = "filterpanel";
            this.filterpanel.Size = new System.Drawing.Size(849, 42);
            this.filterpanel.TabIndex = 2;
            // 
            // label1
            // 
            this.label1.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(710, 12);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(123, 13);
            this.label1.TabIndex = 6;
            this.label1.Text = "(Alerts, Individual Issues)";
            // 
            // informationalcountlabel
            // 
            this.informationalcountlabel.AutoSize = true;
            this.informationalcountlabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.informationalcountlabel.ForeColor = System.Drawing.Color.Green;
            this.informationalcountlabel.Location = new System.Drawing.Point(453, 12);
            this.informationalcountlabel.Name = "informationalcountlabel";
            this.informationalcountlabel.Size = new System.Drawing.Size(70, 13);
            this.informationalcountlabel.TabIndex = 5;
            this.informationalcountlabel.Text = "Informational:";
            this.informationalcountlabel.Click += new System.EventHandler(this.informationalcountlabel_Click);
            // 
            // noiselabel
            // 
            this.noiselabel.AutoSize = true;
            this.noiselabel.Location = new System.Drawing.Point(3, 12);
            this.noiselabel.Name = "noiselabel";
            this.noiselabel.Size = new System.Drawing.Size(59, 13);
            this.noiselabel.TabIndex = 0;
            this.noiselabel.Text = " Alert Filter:";
            // 
            // lowcountlabel
            // 
            this.lowcountlabel.AutoSize = true;
            this.lowcountlabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lowcountlabel.ForeColor = System.Drawing.Color.Blue;
            this.lowcountlabel.Location = new System.Drawing.Point(373, 12);
            this.lowcountlabel.Name = "lowcountlabel";
            this.lowcountlabel.Size = new System.Drawing.Size(30, 13);
            this.lowcountlabel.TabIndex = 4;
            this.lowcountlabel.Text = "Low:";
            this.lowcountlabel.Click += new System.EventHandler(this.lowcountlabel_Click);
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
            this.noisereductioncomboBox.Location = new System.Drawing.Point(68, 9);
            this.noisereductioncomboBox.Name = "noisereductioncomboBox";
            this.noisereductioncomboBox.Size = new System.Drawing.Size(121, 21);
            this.noisereductioncomboBox.TabIndex = 1;
            this.noisereductioncomboBox.ValueMember = "Informational";
            this.noisereductioncomboBox.SelectedIndexChanged += new System.EventHandler(this.comboBox1_SelectedIndexChanged);
            // 
            // mediumcountlabel
            // 
            this.mediumcountlabel.AutoSize = true;
            this.mediumcountlabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.mediumcountlabel.ForeColor = System.Drawing.Color.Orange;
            this.mediumcountlabel.Location = new System.Drawing.Point(282, 12);
            this.mediumcountlabel.Name = "mediumcountlabel";
            this.mediumcountlabel.Size = new System.Drawing.Size(47, 13);
            this.mediumcountlabel.TabIndex = 3;
            this.mediumcountlabel.Text = "Medium:";
            this.mediumcountlabel.Click += new System.EventHandler(this.mediumcountlabel_Click);
            // 
            // highcountlabel
            // 
            this.highcountlabel.AutoSize = true;
            this.highcountlabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.highcountlabel.ForeColor = System.Drawing.Color.Red;
            this.highcountlabel.Location = new System.Drawing.Point(205, 12);
            this.highcountlabel.Name = "highcountlabel";
            this.highcountlabel.Size = new System.Drawing.Size(35, 13);
            this.highcountlabel.TabIndex = 2;
            this.highcountlabel.Text = "High: ";
            this.highcountlabel.Click += new System.EventHandler(this.highcountlabel_Click);
            // 
            // WatcherResultsControl
            // 
            this.BackColor = System.Drawing.SystemColors.Window;
            this.Controls.Add(this.lowerpanel);
            this.DoubleBuffered = true;
            this.Margin = new System.Windows.Forms.Padding(0);
            this.Name = "WatcherResultsControl";
            this.Size = new System.Drawing.Size(851, 653);
            this.resultPanel.ResumeLayout(false);
            this.resultPanel.PerformLayout();
            this.lowerpanel.ResumeLayout(false);
            this.splitContainer.Panel1.ResumeLayout(false);
            this.splitContainer.Panel2.ResumeLayout(false);
            this.splitContainer.ResumeLayout(false);
            this.buttonpanel.ResumeLayout(false);
            this.buttonpanel.PerformLayout();
            this.filterpanel.ResumeLayout(false);
            this.filterpanel.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();
#else
        {
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(WatcherResultsControl));
            this.resultPanel = new System.Windows.Forms.Panel();
            this.alertTextBox = new System.Windows.Forms.TextBox();
            this.referencepanel = new System.Windows.Forms.Panel();
            this.reflinkLabel = new System.Windows.Forms.LinkLabel();
            this.referencelabel = new System.Windows.Forms.Label();
            this.pnlCopyright = new System.Windows.Forms.Panel();
            this.panel1 = new System.Windows.Forms.Panel();
            this.label2 = new System.Windows.Forms.Label();
            this.linkLabel2 = new System.Windows.Forms.LinkLabel();
            this.pictureBox1 = new System.Windows.Forms.PictureBox();
            this.label3 = new System.Windows.Forms.Label();
            this.rightslabel = new System.Windows.Forms.Label();
            this.linkLabel1 = new System.Windows.Forms.LinkLabel();
            this.pbCasaba = new System.Windows.Forms.PictureBox();
            this.copyrightlabel = new System.Windows.Forms.Label();
            this.lowerpanel = new System.Windows.Forms.Panel();
            this.splitContainer = new System.Windows.Forms.SplitContainer();
            this.alertListView = new System.Windows.Forms.ListView();
            this.severityColumnHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.sessionIdColumnHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.typeColumnHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.urlColumnHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.buttonpanel = new System.Windows.Forms.Panel();
            this.exportlabel = new System.Windows.Forms.Label();
            this.cbExportMethod = new System.Windows.Forms.ComboBox();
            this.FileSaveButton = new System.Windows.Forms.Button();
            this.autoscrollcheckBox = new System.Windows.Forms.CheckBox();
            this.filterpanel = new System.Windows.Forms.Panel();
            this.informationalcountlabel = new System.Windows.Forms.Label();
            this.btnClearResults = new System.Windows.Forms.Button();
            this.noiselabel = new System.Windows.Forms.Label();
            this.lowcountlabel = new System.Windows.Forms.Label();
            this.noisereductioncomboBox = new System.Windows.Forms.ComboBox();
            this.mediumcountlabel = new System.Windows.Forms.Label();
            this.highcountlabel = new System.Windows.Forms.Label();
            this.toolTipResultsControl = new System.Windows.Forms.ToolTip(this.components);
            this.resultPanel.SuspendLayout();
            this.referencepanel.SuspendLayout();
            this.pnlCopyright.SuspendLayout();
            this.panel1.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox1)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.pbCasaba)).BeginInit();
            this.lowerpanel.SuspendLayout();
            this.splitContainer.Panel1.SuspendLayout();
            this.splitContainer.Panel2.SuspendLayout();
            this.splitContainer.SuspendLayout();
            this.buttonpanel.SuspendLayout();
            this.filterpanel.SuspendLayout();
            this.SuspendLayout();
            // 
            // resultPanel
            // 
            this.resultPanel.Controls.Add(this.alertTextBox);
            this.resultPanel.Controls.Add(this.referencepanel);
            this.resultPanel.Controls.Add(this.pnlCopyright);
            this.resultPanel.Dock = System.Windows.Forms.DockStyle.Fill;
            this.resultPanel.Location = new System.Drawing.Point(0, 0);
            this.resultPanel.Margin = new System.Windows.Forms.Padding(0);
            this.resultPanel.Name = "resultPanel";
            this.resultPanel.Size = new System.Drawing.Size(851, 311);
            this.resultPanel.TabIndex = 3;
            // 
            // alertTextBox
            // 
            this.alertTextBox.BackColor = System.Drawing.SystemColors.Control;
            this.alertTextBox.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.alertTextBox.Dock = System.Windows.Forms.DockStyle.Fill;
            this.alertTextBox.Location = new System.Drawing.Point(0, 33);
            this.alertTextBox.Margin = new System.Windows.Forms.Padding(0);
            this.alertTextBox.Multiline = true;
            this.alertTextBox.Name = "alertTextBox";
            this.alertTextBox.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.alertTextBox.Size = new System.Drawing.Size(851, 223);
            this.alertTextBox.TabIndex = 0;
            this.alertTextBox.KeyDown += new System.Windows.Forms.KeyEventHandler(this.resultcopyToClipboard);
            // 
            // referencepanel
            // 
            this.referencepanel.BackColor = System.Drawing.Color.LightGray;
            this.referencepanel.Controls.Add(this.reflinkLabel);
            this.referencepanel.Controls.Add(this.referencelabel);
            this.referencepanel.Dock = System.Windows.Forms.DockStyle.Top;
            this.referencepanel.Location = new System.Drawing.Point(0, 0);
            this.referencepanel.Name = "referencepanel";
            this.referencepanel.Size = new System.Drawing.Size(851, 33);
            this.referencepanel.TabIndex = 8;
            // 
            // reflinkLabel
            // 
            this.reflinkLabel.AutoSize = true;
            this.reflinkLabel.Location = new System.Drawing.Point(71, 10);
            this.reflinkLabel.Name = "reflinkLabel";
            this.reflinkLabel.Size = new System.Drawing.Size(0, 13);
            this.reflinkLabel.TabIndex = 2;
            this.reflinkLabel.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.reflinkLabel_LinkClicked);
            // 
            // referencelabel
            // 
            this.referencelabel.AutoSize = true;
            this.referencelabel.Location = new System.Drawing.Point(3, 10);
            this.referencelabel.Name = "referencelabel";
            this.referencelabel.Size = new System.Drawing.Size(63, 13);
            this.referencelabel.TabIndex = 1;
            this.referencelabel.Text = "Reference: ";
            // 
            // pnlCopyright
            // 
            this.pnlCopyright.BackColor = System.Drawing.Color.Transparent;
            this.pnlCopyright.Controls.Add(this.panel1);
            this.pnlCopyright.Controls.Add(this.rightslabel);
            this.pnlCopyright.Controls.Add(this.linkLabel1);
            this.pnlCopyright.Controls.Add(this.pbCasaba);
            this.pnlCopyright.Controls.Add(this.copyrightlabel);
            this.pnlCopyright.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.pnlCopyright.Location = new System.Drawing.Point(0, 256);
            this.pnlCopyright.Margin = new System.Windows.Forms.Padding(0);
            this.pnlCopyright.Name = "pnlCopyright";
            this.pnlCopyright.Size = new System.Drawing.Size(851, 55);
            this.pnlCopyright.TabIndex = 7;
            // 
            // panel1
            // 
            this.panel1.BackColor = System.Drawing.Color.Transparent;
            this.panel1.Controls.Add(this.label2);
            this.panel1.Controls.Add(this.linkLabel2);
            this.panel1.Controls.Add(this.pictureBox1);
            this.panel1.Controls.Add(this.label3);
            this.panel1.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.panel1.Location = new System.Drawing.Point(0, 0);
            this.panel1.Margin = new System.Windows.Forms.Padding(0);
            this.panel1.Name = "panel1";
            this.panel1.Size = new System.Drawing.Size(851, 55);
            this.panel1.TabIndex = 8;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(500, 20);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(93, 13);
            this.label2.TabIndex = 6;
            this.label2.Text = "All rights reserved.";
            // 
            // linkLabel2
            // 
            this.linkLabel2.AutoSize = true;
            this.linkLabel2.BackColor = System.Drawing.Color.Transparent;
            this.linkLabel2.Location = new System.Drawing.Point(385, 20);
            this.linkLabel2.Margin = new System.Windows.Forms.Padding(6, 0, 6, 0);
            this.linkLabel2.Name = "linkLabel2";
            this.linkLabel2.Size = new System.Drawing.Size(112, 13);
            this.linkLabel2.TabIndex = 1;
            this.linkLabel2.TabStop = true;
            this.linkLabel2.Text = "Casaba Security, LLC.";
            this.linkLabel2.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.linkLabel_LinkClicked);
            // 
            // pictureBox1
            // 
            this.pictureBox1.BackColor = System.Drawing.Color.Transparent;
            this.pictureBox1.Dock = System.Windows.Forms.DockStyle.Left;
            this.pictureBox1.Image = ((System.Drawing.Image)(resources.GetObject("pictureBox1.Image")));
            this.pictureBox1.Location = new System.Drawing.Point(0, 0);
            this.pictureBox1.Name = "pictureBox1";
            this.pictureBox1.Size = new System.Drawing.Size(111, 55);
            this.pictureBox1.SizeMode = System.Windows.Forms.PictureBoxSizeMode.CenterImage;
            this.pictureBox1.TabIndex = 5;
            this.pictureBox1.TabStop = false;
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(113, 20);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(228, 13);
            this.label3.TabIndex = 0;
            this.label3.Text = "Watcher Web Security Tool, Copyright © 2010";
            // 
            // rightslabel
            // 
            this.rightslabel.AutoSize = true;
            this.rightslabel.Location = new System.Drawing.Point(413, 24);
            this.rightslabel.Name = "rightslabel";
            this.rightslabel.Size = new System.Drawing.Size(93, 13);
            this.rightslabel.TabIndex = 6;
            this.rightslabel.Text = "All rights reserved.";
            // 
            // linkLabel1
            // 
            this.linkLabel1.AutoSize = true;
            this.linkLabel1.BackColor = System.Drawing.Color.Transparent;
            this.linkLabel1.Location = new System.Drawing.Point(298, 24);
            this.linkLabel1.Margin = new System.Windows.Forms.Padding(6, 0, 6, 0);
            this.linkLabel1.Name = "linkLabel1";
            this.linkLabel1.Size = new System.Drawing.Size(112, 13);
            this.linkLabel1.TabIndex = 1;
            this.linkLabel1.TabStop = true;
            this.linkLabel1.Text = "Casaba Security, LLC.";
            // 
            // pbCasaba
            // 
            this.pbCasaba.BackColor = System.Drawing.Color.Transparent;
            this.pbCasaba.Image = ((System.Drawing.Image)(resources.GetObject("pbCasaba.Image")));
            this.pbCasaba.Location = new System.Drawing.Point(0, 0);
            this.pbCasaba.Name = "pbCasaba";
            this.pbCasaba.Size = new System.Drawing.Size(55, 55);
            this.pbCasaba.SizeMode = System.Windows.Forms.PictureBoxSizeMode.CenterImage;
            this.pbCasaba.TabIndex = 5;
            this.pbCasaba.TabStop = false;
            // 
            // copyrightlabel
            // 
            this.copyrightlabel.AutoSize = true;
            this.copyrightlabel.Location = new System.Drawing.Point(61, 24);
            this.copyrightlabel.Name = "copyrightlabel";
            this.copyrightlabel.Size = new System.Drawing.Size(228, 13);
            this.copyrightlabel.TabIndex = 0;
            this.copyrightlabel.Text = "Watcher Web Security Tool, Copyright © 2010";
            // 
            // lowerpanel
            // 
            this.lowerpanel.AutoSize = true;
            this.lowerpanel.BackColor = System.Drawing.Color.Transparent;
            this.lowerpanel.Controls.Add(this.splitContainer);
            this.lowerpanel.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lowerpanel.Location = new System.Drawing.Point(0, 0);
            this.lowerpanel.Margin = new System.Windows.Forms.Padding(0);
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
            this.splitContainer.Panel1.Controls.Add(this.alertListView);
            this.splitContainer.Panel1.Controls.Add(this.buttonpanel);
            this.splitContainer.Panel1.Controls.Add(this.filterpanel);
            // 
            // splitContainer.Panel2
            // 
            this.splitContainer.Panel2.Controls.Add(this.resultPanel);
            this.splitContainer.Size = new System.Drawing.Size(851, 653);
            this.splitContainer.SplitterDistance = 338;
            this.splitContainer.TabIndex = 0;
            // 
            // alertListView
            // 
            this.alertListView.Activation = System.Windows.Forms.ItemActivation.OneClick;
            this.alertListView.AllowColumnReorder = true;
            this.alertListView.BackColor = System.Drawing.SystemColors.Window;
            this.alertListView.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
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
            this.alertListView.Location = new System.Drawing.Point(0, 63);
            this.alertListView.Margin = new System.Windows.Forms.Padding(0);
            this.alertListView.Name = "alertListView";
            this.alertListView.Size = new System.Drawing.Size(851, 246);
            this.alertListView.TabIndex = 7;
            this.alertListView.UseCompatibleStateImageBehavior = false;
            this.alertListView.View = System.Windows.Forms.View.Details;
            this.alertListView.ColumnClick += new System.Windows.Forms.ColumnClickEventHandler(this.alertListView_ColumnClick);
            this.alertListView.SelectedIndexChanged += new System.EventHandler(this.alertListView_SelectedIndexChanged);
            this.alertListView.DoubleClick += new System.EventHandler(this.alertListViewDoubleClick);
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
            // buttonpanel
            // 
            this.buttonpanel.BackColor = System.Drawing.Color.Transparent;
            this.buttonpanel.Controls.Add(this.exportlabel);
            this.buttonpanel.Controls.Add(this.cbExportMethod);
            this.buttonpanel.Controls.Add(this.FileSaveButton);
            this.buttonpanel.Controls.Add(this.autoscrollcheckBox);
            this.buttonpanel.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.buttonpanel.Location = new System.Drawing.Point(0, 309);
            this.buttonpanel.Margin = new System.Windows.Forms.Padding(0);
            this.buttonpanel.Name = "buttonpanel";
            this.buttonpanel.Size = new System.Drawing.Size(851, 29);
            this.buttonpanel.TabIndex = 11;
            // 
            // exportlabel
            // 
            this.exportlabel.AutoSize = true;
            this.exportlabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.exportlabel.Location = new System.Drawing.Point(108, 10);
            this.exportlabel.Name = "exportlabel";
            this.exportlabel.Size = new System.Drawing.Size(79, 13);
            this.exportlabel.TabIndex = 12;
            this.exportlabel.Text = "Export Method:";
            // 
            // cbExportMethod
            // 
            this.cbExportMethod.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbExportMethod.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.cbExportMethod.FormattingEnabled = true;
            this.cbExportMethod.ItemHeight = 13;
            this.cbExportMethod.Location = new System.Drawing.Point(190, 7);
            this.cbExportMethod.Name = "cbExportMethod";
            this.cbExportMethod.Size = new System.Drawing.Size(165, 21);
            this.cbExportMethod.Sorted = true;
            this.cbExportMethod.TabIndex = 11;
            this.cbExportMethod.SelectedIndexChanged += new System.EventHandler(this.savemethodcomboBox_SelectedIndexChanged);
            // 
            // FileSaveButton
            // 
            this.FileSaveButton.Location = new System.Drawing.Point(3, 5);
            this.FileSaveButton.Name = "FileSaveButton";
            this.FileSaveButton.Size = new System.Drawing.Size(95, 23);
            this.FileSaveButton.TabIndex = 9;
            this.FileSaveButton.Text = "Export Findings";
            this.toolTipResultsControl.SetToolTip(this.FileSaveButton, "Export all results using chosen save method.");
            this.FileSaveButton.UseVisualStyleBackColor = true;
            this.FileSaveButton.Click += new System.EventHandler(this.FileSaveButton_Click);
            // 
            // autoscrollcheckBox
            // 
            this.autoscrollcheckBox.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.autoscrollcheckBox.AutoSize = true;
            this.autoscrollcheckBox.Location = new System.Drawing.Point(774, 9);
            this.autoscrollcheckBox.Name = "autoscrollcheckBox";
            this.autoscrollcheckBox.Size = new System.Drawing.Size(74, 17);
            this.autoscrollcheckBox.TabIndex = 10;
            this.autoscrollcheckBox.Text = "AutoScroll";
            this.toolTipResultsControl.SetToolTip(this.autoscrollcheckBox, "When checked Watcher will place the latest alerts and the bottom of the displayed" +
                    " list of selectedResults.");
            this.autoscrollcheckBox.UseVisualStyleBackColor = true;
            this.autoscrollcheckBox.CheckedChanged += new System.EventHandler(this.autoscrollcheckBox_CheckedChanged);
            // 
            // filterpanel
            // 
            this.filterpanel.BackColor = System.Drawing.Color.Transparent;
            this.filterpanel.Controls.Add(this.informationalcountlabel);
            this.filterpanel.Controls.Add(this.btnClearResults);
            this.filterpanel.Controls.Add(this.noiselabel);
            this.filterpanel.Controls.Add(this.lowcountlabel);
            this.filterpanel.Controls.Add(this.noisereductioncomboBox);
            this.filterpanel.Controls.Add(this.mediumcountlabel);
            this.filterpanel.Controls.Add(this.highcountlabel);
            this.filterpanel.Dock = System.Windows.Forms.DockStyle.Top;
            this.filterpanel.Location = new System.Drawing.Point(0, 0);
            this.filterpanel.Name = "filterpanel";
            this.filterpanel.Size = new System.Drawing.Size(851, 63);
            this.filterpanel.TabIndex = 2;
            this.toolTipResultsControl.SetToolTip(this.filterpanel, "Clears any selected results, or all results if none are selected.");
            // 
            // informationalcountlabel
            // 
            this.informationalcountlabel.AutoSize = true;
            this.informationalcountlabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.informationalcountlabel.ForeColor = System.Drawing.Color.Green;
            this.informationalcountlabel.Location = new System.Drawing.Point(453, 12);
            this.informationalcountlabel.Name = "informationalcountlabel";
            this.informationalcountlabel.Size = new System.Drawing.Size(70, 13);
            this.informationalcountlabel.TabIndex = 5;
            this.informationalcountlabel.Text = "Informational:";
            this.toolTipResultsControl.SetToolTip(this.informationalcountlabel, "(Alerts, Individual Issues)");
            this.informationalcountlabel.Click += new System.EventHandler(this.informationalcountlabel_Click);
            // 
            // btnClearResults
            // 
            this.btnClearResults.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.btnClearResults.AutoSize = true;
            this.btnClearResults.Location = new System.Drawing.Point(6, 35);
            this.btnClearResults.Name = "btnClearResults";
            this.btnClearResults.Size = new System.Drawing.Size(124, 23);
            this.btnClearResults.TabIndex = 8;
            this.btnClearResults.Text = "Clear Selected Results";
            this.toolTipResultsControl.SetToolTip(this.btnClearResults, "Selected selectedResults will be removed. If none are selected all selectedResult" +
                    "s will be removed.");
            this.btnClearResults.UseVisualStyleBackColor = true;
            this.btnClearResults.Click += new System.EventHandler(this.btnClearResults_Click);
            // 
            // noiselabel
            // 
            this.noiselabel.AutoSize = true;
            this.noiselabel.Location = new System.Drawing.Point(3, 12);
            this.noiselabel.Name = "noiselabel";
            this.noiselabel.Size = new System.Drawing.Size(59, 13);
            this.noiselabel.TabIndex = 0;
            this.noiselabel.Text = " Alert Filter:";
            // 
            // lowcountlabel
            // 
            this.lowcountlabel.AutoSize = true;
            this.lowcountlabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lowcountlabel.ForeColor = System.Drawing.Color.Blue;
            this.lowcountlabel.Location = new System.Drawing.Point(373, 12);
            this.lowcountlabel.Name = "lowcountlabel";
            this.lowcountlabel.Size = new System.Drawing.Size(30, 13);
            this.lowcountlabel.TabIndex = 4;
            this.lowcountlabel.Text = "Low:";
            this.toolTipResultsControl.SetToolTip(this.lowcountlabel, "(Alerts, Individual Issues)");
            this.lowcountlabel.Click += new System.EventHandler(this.lowcountlabel_Click);
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
            this.noisereductioncomboBox.Location = new System.Drawing.Point(68, 9);
            this.noisereductioncomboBox.Name = "noisereductioncomboBox";
            this.noisereductioncomboBox.Size = new System.Drawing.Size(121, 21);
            this.noisereductioncomboBox.TabIndex = 1;
            this.toolTipResultsControl.SetToolTip(this.noisereductioncomboBox, "Results of the selected value and higher only will be displayed.");
            this.noisereductioncomboBox.ValueMember = "Informational";
            this.noisereductioncomboBox.SelectedIndexChanged += new System.EventHandler(this.comboBox1_SelectedIndexChanged);
            // 
            // mediumcountlabel
            // 
            this.mediumcountlabel.AutoSize = true;
            this.mediumcountlabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.mediumcountlabel.ForeColor = System.Drawing.Color.Orange;
            this.mediumcountlabel.Location = new System.Drawing.Point(282, 12);
            this.mediumcountlabel.Name = "mediumcountlabel";
            this.mediumcountlabel.Size = new System.Drawing.Size(47, 13);
            this.mediumcountlabel.TabIndex = 3;
            this.mediumcountlabel.Text = "Medium:";
            this.toolTipResultsControl.SetToolTip(this.mediumcountlabel, "(Alerts, Individual Issues)");
            this.mediumcountlabel.Click += new System.EventHandler(this.mediumcountlabel_Click);
            // 
            // highcountlabel
            // 
            this.highcountlabel.AutoSize = true;
            this.highcountlabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.highcountlabel.ForeColor = System.Drawing.Color.Red;
            this.highcountlabel.Location = new System.Drawing.Point(205, 12);
            this.highcountlabel.Name = "highcountlabel";
            this.highcountlabel.Size = new System.Drawing.Size(35, 13);
            this.highcountlabel.TabIndex = 2;
            this.highcountlabel.Text = "High: ";
            this.toolTipResultsControl.SetToolTip(this.highcountlabel, "(Alerts, Individual Issues)");
            this.highcountlabel.Click += new System.EventHandler(this.highcountlabel_Click);
            // 
            // WatcherResultsControl
            // 
            this.BackColor = System.Drawing.Color.Transparent;
            this.Controls.Add(this.lowerpanel);
            this.Margin = new System.Windows.Forms.Padding(0);
            this.Name = "WatcherResultsControl";
            this.Size = new System.Drawing.Size(851, 653);
            this.resultPanel.ResumeLayout(false);
            this.resultPanel.PerformLayout();
            this.referencepanel.ResumeLayout(false);
            this.referencepanel.PerformLayout();
            this.pnlCopyright.ResumeLayout(false);
            this.pnlCopyright.PerformLayout();
            this.panel1.ResumeLayout(false);
            this.panel1.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox1)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.pbCasaba)).EndInit();
            this.lowerpanel.ResumeLayout(false);
            this.splitContainer.Panel1.ResumeLayout(false);
            this.splitContainer.Panel2.ResumeLayout(false);
            this.splitContainer.ResumeLayout(false);
            this.buttonpanel.ResumeLayout(false);
            this.buttonpanel.PerformLayout();
            this.filterpanel.ResumeLayout(false);
            this.filterpanel.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }
#endif

        #endregion

        public Panel resultPanel;
        private TextBox alertTextBox;
        private Panel lowerpanel;
        private SplitContainer splitContainer;
        public ListView alertListView;
        public ColumnHeader severityColumnHeader;
        public ColumnHeader sessionIdColumnHeader;
        public ColumnHeader typeColumnHeader;
        public ColumnHeader urlColumnHeader;
        private Label informationalcountlabel;
        private Label lowcountlabel;
        private Label mediumcountlabel;
        private Label highcountlabel;
        private CheckBox autoscrollcheckBox;
        public Button FileSaveButton;
        private Label noiselabel;
        public Button btnClearResults;
        public ComboBox noisereductioncomboBox;
        private Panel filterpanel;
        private Panel buttonpanel;
        private ToolTip toolTipResultsControl;
        private Panel pnlCopyright;
        private Label rightslabel;
        public LinkLabel linkLabel1;
        private PictureBox pbCasaba;
        private Label copyrightlabel;
        private Panel panel1;
        private Label label2;
        public LinkLabel linkLabel2;
        private PictureBox pictureBox1;
        private Label label3;
        private ComboBox cbExportMethod;
        private Label exportlabel;
        private Panel referencepanel;
        private Label referencelabel;
        private LinkLabel reflinkLabel;
       
        public class AlertListViewItem : ListViewItem
        {
            #region Fields
            private Int32 _id;
            private WatcherResultSeverity _severity;
            private String _url;
            private String _name;
            private String _description;
            private Int32 _count;
            private String _reflink;
            #endregion

            #region Ctor(s)

            public AlertListViewItem(WatcherResultSeverity severity, Int32 id, String name, String url, String description, int count)
                : this(severity, id, name, url, description, count, String.Empty) {}

            public AlertListViewItem(WatcherResultSeverity severity, Int32 id, String name, String url, String description, int count, String reflink)
            {
                _id = id;
                _severity = severity;
                _url = url;
                _name = name;
                _description = description;
                _count = count;
                _reflink = reflink;

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

            public String refLink
            {
                get { return _reflink; }
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