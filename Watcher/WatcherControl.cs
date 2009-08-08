// WATCHER
//
// WatcherControl.cs
// Main implementation of WatcherControl UI.
//
// Copyright (c) 2009 Casaba Security, LLC
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

        #endregion

        #region Private Method(s)

        /// <summary>
        /// Initialize the control for display in the Fiddler UI.
        /// </summary>
        private void InitializeTabPages()
        {
            // Instantiate the Watcher UI tab in preparation to be added to the Fiddler UI
            _watcherTab.AutoScroll = false;
            _watcherTab.BackColor = Color.LightGray;

            // Add our custom icon
            FiddlerApplication.UI.imglSessionIcons.Images.Add(Properties.Resources.Casaba);
            _watcherTab.ImageIndex = (FiddlerApplication.UI.imglSessionIcons.Images.Count) - 1;

            // Add the tab to the Fiddler UI
            FiddlerApplication.UI.tabsViews.TabPages.Add(_watcherTab);

            // Initialize the control
            this.BackColor = Color.LightGray;
            this.AutoSize = true;
            this.BorderStyle = System.Windows.Forms.BorderStyle.Fixed3D;
            this.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            this.Dock = DockStyle.Fill;

            // Add the control to the Fiddler tab
            _watcherTab.Controls.Add(this);
        }

        #endregion
    }
}
