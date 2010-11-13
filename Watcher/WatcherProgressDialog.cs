using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Data;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace CasabaSecurity.Web.Watcher
{
    // TODO: This should be an internal class, and managed by a proxy class (mainly to ensure we're running on the UI thread).
    public partial class WatcherProgressDialog : Form
    {
        #region Field(s)
        // private const byte _increment = 10;      // Default amount to increment the progress bar
        private int _increment;

        #endregion

        #region Ctor/Dtor(s)
        
        public WatcherProgressDialog()
        {
            InitializeComponent();
        }
        
        #endregion

        #region Public Properties

        /// <summary>
        /// Maximum range for the progress bar.
        /// </summary>
        public int MaximumRange
        {
            get { return progressBar1.Maximum; }
            set { progressBar1.Maximum = value; }
        }

        /// <summary>
        /// Minimum range for the progress bar.
        /// </summary>
        public int MinimumRange
        {
            get { return progressBar1.Minimum; }
            set { progressBar1.Minimum = value; }
        }

        /// <summary>
        /// Get/set the current position of the progress bar.
        /// </summary>
        public int ProgressValue
        {
            get { return progressBar1.Value; }
            set 
            {
                // Adjust the progress bar position so that it does not exceed the
                // progress bar maximum value.
                // TODO: This code is somewhat redundant, given the code in UpdateProgressInternal().
                if (value > progressBar1.Maximum || value < progressBar1.Minimum)
                {
                    Random rnd = new Random();
                    //progressBar1.Value = rnd.Next(progressBar1.Minimum, progressBar1.Maximum);
                }

                UpdateProgress();
            }
        }

        /// <summary>
        /// How much do you want to increment by?  
        /// </summary>
        public int Increment
        {
            get { return _increment; }
            set { _increment = value; }
        }

        #endregion

        #region Public Method(s)

        // TODO: also need Text override
        // TODO: also need a "clear" override
        public new void Show()
        {
            if (this.InvokeRequired)
            {
                this.BeginInvoke(new ShowCallback(base.Show));
            }
            else
            {
                base.Show();
            }
        }

        /// <summary>
        /// Change the progress disalog to display the specified description, and move the
        /// progress bar forward.
        /// </summary>
        /// <param name="description">The text to display to the user.  If this parameter is null, the existing description does not change.</param>
        public void UpdateProgress(String description)
        {
            // A control cannot be updated from a non-UI thread.  If the InvokeRequired property is set,
            // we are on a non-UI thread and must post a message to the UI thread to handle the update on
            // our behalf.  According to Richter, this is one of the few instances where BeginInvoke can
            // be called without a corresponding EndInvoke().
            if (this.InvokeRequired)
            {
                // We're not the UI thread: marshall an update to the control asynchronously
                this.BeginInvoke(new UpdateProgressCallback(this.UpdateProgressInternal), new Object[] { description });
            }
            else
            {
                // We're the UI thread, update the control directly
                UpdateProgressInternal(description);
            }
        }

        /// <summary>
        /// Update the progress bar without changing the description.
        /// </summary>
        public void UpdateProgress()
        {
            UpdateProgress(null);
        }

        #endregion

        #region Private Method(s)

        /// <summary>
        /// This is the implementation of the progress bar update logic.
        /// </summary>
        /// <param name="description">The text to display to the user.  If this parameter is null, the existing description does not change.</param>
        private void UpdateProgressInternal(String description)
        {
            // If the argument is null, keep the description the same
            if (!String.IsNullOrEmpty(description))
            {
                labelOperation.Text = description;
            }

            // Adjust the progress bar position so that it does not exceed the
            // progress bar maximum value.
            if (progressBar1.Value + _increment > progressBar1.Maximum)
            {
                progressBar1.Value = progressBar1.Maximum - _increment;
            }

            // Increment the progress bar position
            progressBar1.Value = progressBar1.Value + _increment;

            // Redraw and add a bit of pause.
            Refresh();
            Thread.Sleep(175);
        }

        #endregion

        #region Delegate(s)

        /// <summary>
        /// This callback is used to update UI controls from a non-UI thread.
        /// </summary>
        private delegate void UpdateProgressCallback(String description);

        /// <summary>
        /// This callback is used to display the dialog to the user when called from a non-UI thread.
        /// </summary>
        private delegate void ShowCallback();

        #endregion
    }
}
