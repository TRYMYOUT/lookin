// WATCHER
//
// WatcherControl.cs
// Main implementation of WatcherControl UI.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Data;
using System.Text;
using System.Windows.Forms;
using Fiddler;

namespace CasabaSecurity.Web.Watcher
{
    /// <summary>
    /// This control is aggregated by the TabPage shown in the Fiddler UI.
    /// </summary>
    /// TODO: public->internal
    public partial class WatcherControl : UserControl
    {
        #region Fields
        private Object _lock = new Object();                                    // Used to synchronize additions to the "alerts" box
        private TabPage _watcherTab = new TabPage("Watcher");                   // This is the main Watcher tab shown in Fiddler
        #endregion

        #region Ctor(s)
        public WatcherControl()
        {
            InitializeComponent();
            InitializeTabPages();
        }
        #endregion

        #region Public Properties

        /// <summary>
        /// This property returns a reference the Watcher Results tab.
        /// </summary>
        public WatcherResultsControl WatcherResultsControl
        {
            get { return this.watcherResultsTab; }
        }

        /// <summary>
        /// Set BackColor for Watcher.
        /// </summary>
        public Color WatcherResultsControlColor
        {
            get { return this.BackColor; }
            set { this.BackColor = value;
            this.tabPage1.BackColor = value;
            this.tabPage2.BackColor = value;
            this.tabPage3.BackColor = value;
            }
        }

        #endregion

        #region Private Method(s)

        /// <summary>
        /// Initialize the control for display in the Fiddler UI.
        /// </summary>
        private void InitializeTabPages()
        {
            // Initialize the Watcher UI tab in preparation to be added to Fiddler
            _watcherTab.AutoScroll = false;
            _watcherTab.BackColor = Color.Transparent;

            // Add the Watcher icon to the Fiddler tab
            FiddlerApplication.UI.imglSessionIcons.Images.Add(Properties.Resources.Watcher);
            _watcherTab.ImageIndex = FiddlerApplication.UI.imglSessionIcons.Images.Count - 1;

            // Add the tab to Fiddler
            FiddlerApplication.UI.tabsViews.TabPages.Add(_watcherTab);

            // Initialize the control
            this.BackColor = Color.Transparent;
            this.AutoSize = true;
            this.BorderStyle = System.Windows.Forms.BorderStyle.Fixed3D;
            this.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            this.Dock = DockStyle.Fill;

            // Add the tab control Fiddler
            _watcherTab.Controls.Add(this);
        }

        #endregion
    }
}
