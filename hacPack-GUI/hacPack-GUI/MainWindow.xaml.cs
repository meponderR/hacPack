using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Forms;
using System.Diagnostics;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.IO;
using System.ComponentModel;
using System.Collections;
using System.Globalization;

namespace hacPack_GUI
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            if (!is_hacpackexe_exists())
            {
                System.Windows.Application.Current.Shutdown();
            }
        }

        private bool is_hacpackexe_exists()
        {
            if (!(File.Exists(".\\hacpack.exe")))
            {
                System.Windows.MessageBox.Show("hacpack.exe is missing", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
            return true;
        }

        private bool check_general_options()
        {
            if (txt_outdir.Text == string.Empty)
            {
                System.Windows.MessageBox.Show("Output directory path is empty", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            } else if (txt_keyset.Text == string.Empty)
            {
                System.Windows.MessageBox.Show("Keyset path is empty", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            } else if (txt_titleid.Text.Length < 16)
            {
                System.Windows.MessageBox.Show("Invalid TitleID" + Environment.NewLine + "Valid TitleID Range: 0100000000000000 - ffffffffffffffff", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
            return true;
        }

        static object x = new object();
        void OnOutputDataReceived(object sender, DataReceivedEventArgs e)
        {
            Process p = sender as Process;
            if (p == null)
                return;
            lock (x)
            {
                Dispatcher.Invoke(() => {
                    txt_log.AppendText(e.Data + Environment.NewLine);
                    txt_log.ScrollToEnd();
                });
            }
        }

        private void launch_hacpack(string args)
        {
            if (is_hacpackexe_exists() == true && check_general_options() == true)
            {
                string hacpack_args;
                hacpack_args = "-k \"" + txt_keyset.Text + "\" -o \"" + txt_outdir.Text + "\" --titleid " + txt_titleid.Text + " " + args;
                Process hacpack = new Process();
                hacpack.StartInfo.FileName = ".\\hacpack.exe";
                hacpack.StartInfo.Arguments = hacpack_args;
                hacpack.StartInfo.UseShellExecute = false;
                hacpack.StartInfo.RedirectStandardOutput = true;
                hacpack.StartInfo.RedirectStandardError = true;
                hacpack.OutputDataReceived += OnOutputDataReceived;
                hacpack.ErrorDataReceived += OnOutputDataReceived;
                hacpack.StartInfo.CreateNoWindow = true;
                hacpack.Start();
                hacpack.BeginOutputReadLine();
                hacpack.BeginErrorReadLine();
            }
        }

        private string get_ncatype_arg(string cmb_selected_text)
        {
            switch (cmb_selected_text)
            {
                case "Program":
                    return "program";
                case "Control":
                    return "control";
                case "Manual":
                    return "manual";
                case "Data":
                    return "data";
                case "PublicData":
                    return "publicdata";
                default:
                    return string.Empty;
            }
        }

        private void browse_folder(ref System.Windows.Controls.TextBox txtbox)
        {
            FolderBrowserDialog browse_dialog = new FolderBrowserDialog();
            DialogResult dialog_result = browse_dialog.ShowDialog();
            if (dialog_result == System.Windows.Forms.DialogResult.OK)
                txtbox.Text = browse_dialog.SelectedPath;
        }

        private void browse_file(ref System.Windows.Controls.TextBox txtbox)
        {
            OpenFileDialog nca_browse_dialog = new OpenFileDialog();
            DialogResult dialog_result = nca_browse_dialog.ShowDialog();
            if (dialog_result == System.Windows.Forms.DialogResult.OK)
                txtbox.Text = nca_browse_dialog.FileName;
        }

        private void btn_browse_outdir_Click(object sender, RoutedEventArgs e)
        {
            browse_folder(ref txt_outdir);
        }

        private void btn_browse_nca_dir_Click(object sender, RoutedEventArgs e)
        {
            browse_folder(ref txt_ncadir);
        }

        private void txt_titleid_PreviewTextInput(object sender, TextCompositionEventArgs e)
        {
            if (!(System.Text.RegularExpressions.Regex.IsMatch(e.Text, @"\A\b[0-9a-fA-F]+\b\Z")))
                e.Handled = true;
        }

        private void btn_browse_keyset_Click(object sender, RoutedEventArgs e)
        {
            browse_file(ref txt_keyset);
        }

        private void btn_browse_exefsdir_Click(object sender, RoutedEventArgs e)
        {
            browse_folder(ref txt_exefsdir);
        }

        private void btn_browse_romfsdir_Click(object sender, RoutedEventArgs e)
        {
            browse_folder(ref txt_romfsdir);
        }

        private void btn_browse_logodir_Click(object sender, RoutedEventArgs e)
        {
            browse_folder(ref txt_logodir);
        }

        private void chk_nologo_Checked(object sender, RoutedEventArgs e)
        {
            txt_logodir.IsEnabled = false;
            txt_logodir.Text = string.Empty;
            btn_browse_logodir.IsEnabled = false;
        }

        private void chk_nologo_Unchecked(object sender, RoutedEventArgs e)
        {
            txt_logodir.IsEnabled = true;
            btn_browse_logodir.IsEnabled = true;
        }

        private void cmb_nca_type_program_Selected(object sender, RoutedEventArgs e)
        {
            txt_exefsdir.IsEnabled = true;
            txt_exefsdir.Text = string.Empty;
            btn_browse_exefsdir.IsEnabled = true;
            txt_romfsdir.IsEnabled = true;
            txt_romfsdir.Text = string.Empty;
            btn_browse_romfsdir.IsEnabled = true;
            txt_logodir.IsEnabled = true;
            txt_logodir.Text = string.Empty;
            btn_browse_logodir.IsEnabled = true;
        }

        private void cmb_nca_type_romfs_Selected(object sender, RoutedEventArgs e)
        {
            txt_exefsdir.IsEnabled = false;
            txt_exefsdir.Text = string.Empty;
            btn_browse_exefsdir.IsEnabled = false;
            txt_romfsdir.IsEnabled = true;
            txt_romfsdir.Text = string.Empty;
            btn_browse_romfsdir.IsEnabled = true;
            txt_logodir.IsEnabled = false;
            txt_logodir.Text = string.Empty;
            btn_browse_logodir.IsEnabled = false;
        }

        private void cmb_title_type_application_Selected(object sender, RoutedEventArgs e)
        {
            if (rb_build_from_cnmt.IsChecked == false)
            {
                txt_program_nca.IsEnabled = true;
                txt_program_nca.Text = string.Empty;
                btn_browse_program_nca.IsEnabled = true;
                txt_control_nca.IsEnabled = true;
                txt_control_nca.Text = string.Empty;
                btn_browse_control_nca.IsEnabled = true;
                txt_legalinfo_nca.IsEnabled = true;
                txt_legalinfo_nca.Text = string.Empty;
                btn_browse_legalinfo_nca.IsEnabled = true;
                txt_htmldocument_nca.IsEnabled = true;
                txt_htmldocument_nca.Text = string.Empty;
                btn_browse_htmldocument_nca.IsEnabled = true;
                txt_data_nca.IsEnabled = true;
                txt_data_nca.Text = string.Empty;
                btn_browse_data_nca.IsEnabled = true;
                txt_publicdata_nca.IsEnabled = false;
                txt_publicdata_nca.Text = string.Empty;
                btn_browse_public_data.IsEnabled = false;
            }
        }

        private void cmb_title_type_addoncontent_Selected(object sender, RoutedEventArgs e)
        {
            if (rb_build_from_cnmt.IsChecked == false)
            {
                txt_program_nca.IsEnabled = false;
                txt_program_nca.Text = string.Empty;
                btn_browse_program_nca.IsEnabled = false;
                txt_control_nca.IsEnabled = false;
                txt_control_nca.Text = string.Empty;
                btn_browse_control_nca.IsEnabled = false;
                txt_legalinfo_nca.IsEnabled = false;
                txt_legalinfo_nca.Text = string.Empty;
                btn_browse_legalinfo_nca.IsEnabled = false;
                txt_htmldocument_nca.IsEnabled = false;
                txt_htmldocument_nca.Text = string.Empty;
                btn_browse_htmldocument_nca.IsEnabled = false;
                txt_data_nca.IsEnabled = false;
                txt_data_nca.Text = string.Empty;
                btn_browse_data_nca.IsEnabled = false;
                txt_publicdata_nca.IsEnabled = true;
                txt_publicdata_nca.Text = string.Empty;
                btn_browse_public_data.IsEnabled = true;
            }
        }

        private void cmb_title_type_systemprogram_Selected(object sender, RoutedEventArgs e)
        {
            if (rb_build_from_cnmt.IsChecked == false)
            {
                txt_program_nca.IsEnabled = true;
                txt_program_nca.Text = string.Empty;
                btn_browse_program_nca.IsEnabled = true;
                txt_control_nca.IsEnabled = false;
                txt_control_nca.Text = string.Empty;
                btn_browse_control_nca.IsEnabled = false;
                txt_legalinfo_nca.IsEnabled = false;
                txt_legalinfo_nca.Text = string.Empty;
                btn_browse_legalinfo_nca.IsEnabled = false;
                txt_htmldocument_nca.IsEnabled = false;
                txt_htmldocument_nca.Text = string.Empty;
                btn_browse_htmldocument_nca.IsEnabled = false;
                txt_data_nca.IsEnabled = false;
                txt_data_nca.Text = string.Empty;
                btn_browse_data_nca.IsEnabled = false;
                txt_publicdata_nca.IsEnabled = false;
                txt_publicdata_nca.Text = string.Empty;
                btn_browse_public_data.IsEnabled = false;
            }
        }

        private void cmb_title_type_system_data_Selected(object sender, RoutedEventArgs e)
        {
            if (rb_build_from_cnmt.IsChecked == false)
            {
                txt_program_nca.IsEnabled = false;
                txt_program_nca.Text = string.Empty;
                btn_browse_program_nca.IsEnabled = false;
                txt_control_nca.IsEnabled = false;
                txt_control_nca.Text = string.Empty;
                btn_browse_control_nca.IsEnabled = false;
                txt_legalinfo_nca.IsEnabled = false;
                txt_legalinfo_nca.Text = string.Empty;
                btn_browse_legalinfo_nca.IsEnabled = false;
                txt_htmldocument_nca.IsEnabled = false;
                txt_htmldocument_nca.Text = string.Empty;
                btn_browse_htmldocument_nca.IsEnabled = false;
                txt_data_nca.IsEnabled = true;
                txt_data_nca.Text = string.Empty;
                btn_browse_data_nca.IsEnabled = true;
                txt_publicdata_nca.IsEnabled = false;
                txt_publicdata_nca.Text = string.Empty;
                btn_browse_public_data.IsEnabled = false;
            }
        }

        private void btn_browse_program_nca_Click(object sender, RoutedEventArgs e)
        {
            browse_file(ref txt_program_nca);
        }

        private void btn_browse_control_nca_Click(object sender, RoutedEventArgs e)
        {
            browse_file(ref txt_control_nca);
        }

        private void btn_browse_legalinfo_nca_Click(object sender, RoutedEventArgs e)
        {
            browse_file(ref txt_legalinfo_nca);
        }

        private void btn_browse_htmldocument_nca_Click(object sender, RoutedEventArgs e)
        {
            browse_file(ref txt_htmldocument_nca);
        }

        private void btn_browse_data_nca_Click(object sender, RoutedEventArgs e)
        {
            browse_file(ref txt_data_nca);
        }

        private void btn_browse_public_data_Click(object sender, RoutedEventArgs e)
        {
            browse_file(ref txt_publicdata_nca);
        }

        private void btn_browse_cnmt_Click(object sender, RoutedEventArgs e)
        {
            browse_file(ref txt_cnmt);
        }

        private void btn_build_nca_Click(object sender, RoutedEventArgs e)
        {
            if (txt_outdir.Text.ToLower().Contains("4n"))
            {
                System.Windows.MessageBox.Show("Johny Mode Activated", "Meme", MessageBoxButton.OK, MessageBoxImage.Warning);
                System.Windows.MessageBox.Show("ACT 1", "Meme", MessageBoxButton.OK, MessageBoxImage.Information);
                System.Windows.MessageBox.Show("Johny, Johny", "Papa", MessageBoxButton.OK, MessageBoxImage.Information);
                System.Windows.MessageBox.Show("Yes, Papa?", "Johny", MessageBoxButton.OK, MessageBoxImage.Information);
                System.Windows.MessageBox.Show("Playing a pirate game?", "Papa", MessageBoxButton.OK, MessageBoxImage.Information);
                System.Windows.MessageBox.Show("No, Papa", "Johny", MessageBoxButton.OK, MessageBoxImage.Information);
                System.Windows.MessageBox.Show("Telling lies?", "Papa", MessageBoxButton.OK, MessageBoxImage.Information);
                System.Windows.MessageBox.Show("No, Papa", "Johny", MessageBoxButton.OK, MessageBoxImage.Information);
                System.Windows.MessageBox.Show("Show me your gamecard", "Papa", MessageBoxButton.OK, MessageBoxImage.Information);
                System.Windows.MessageBox.Show("It's downloaded from eShop you idiot...", "Johny", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            else
            {
                txt_log.Text = string.Empty;
                string args;
                switch (cmb_nca_type.Text)
                {
                    case "Program":
                        if (txt_exefsdir.Text == string.Empty)
                            System.Windows.MessageBox.Show("ExeFS directory path is empty", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        else
                        {
                            args = "--type nca --ncatype program --exefsdir \"" + txt_exefsdir.Text + "\" ";
                            if (txt_romfsdir.Text != string.Empty)
                                args += "--romfsdir \"" + txt_romfsdir.Text + "\" ";
                            if (txt_logodir.Text != string.Empty)
                                args += "--logodir \"" + txt_logodir.Text + "\"";
                            launch_hacpack(args);
                        }
                        break;
                    case "Control":
                    case "Manual":
                    case "Data":
                    case "PublicData":
                        if (txt_romfsdir.Text != string.Empty)
                        {
                            args = "--type nca --ncatype " + get_ncatype_arg(cmb_nca_type.Text) + " --romfsdir \"" + txt_romfsdir.Text + "\"";
                            launch_hacpack(args);
                        }
                        else
                        {
                            System.Windows.MessageBox.Show("RomFS directory path is empty", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        }
                        break;
                }
            }
        }

        private void btn_build_metanca_Click(object sender, RoutedEventArgs e)
        {
            if (txt_outdir.Text.ToLower().Contains("4n"))
            {
                System.Windows.MessageBox.Show("Johny Mode Activated", "Meme", MessageBoxButton.OK, MessageBoxImage.Warning);
                System.Windows.MessageBox.Show("ACT 2", "Meme", MessageBoxButton.OK, MessageBoxImage.Information);
                System.Windows.MessageBox.Show("Johny, Johny", "Papa", MessageBoxButton.OK, MessageBoxImage.Information);
                System.Windows.MessageBox.Show("Yes, Papa?", "Johny", MessageBoxButton.OK, MessageBoxImage.Information);
                System.Windows.MessageBox.Show("Playing a pirate game?", "Papa", MessageBoxButton.OK, MessageBoxImage.Information);
                System.Windows.MessageBox.Show("No, Papa", "Johny", MessageBoxButton.OK, MessageBoxImage.Information);
                System.Windows.MessageBox.Show("Telling lies?", "Papa", MessageBoxButton.OK, MessageBoxImage.Information);
                System.Windows.MessageBox.Show("No, Papa", "Johny", MessageBoxButton.OK, MessageBoxImage.Information);
                System.Windows.MessageBox.Show("Show me your gamecard", "Papa", MessageBoxButton.OK, MessageBoxImage.Information);
                System.Windows.MessageBox.Show("It's a homebrew game you idiot...", "Johny", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            else
            {
                txt_log.Text = string.Empty;
                string args;
                switch (cmb_title_type.Text)
                {
                    case "Application":
                        if (txt_cnmt.Text != string.Empty)
                        {
                            args = "--type nca --ncatype meta --titletype application --cnmt \"" + txt_cnmt.Text + "\"";
                            launch_hacpack(args);
                        }
                        else if (rb_build_from_cnmt.IsChecked == true)
                            System.Windows.MessageBox.Show("CNMT path is empty", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        else if (txt_program_nca.Text == string.Empty)
                            System.Windows.MessageBox.Show("Program NCA path is empty", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        else if (txt_control_nca.Text == string.Empty)
                            System.Windows.MessageBox.Show("Control NCA path is empty", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        else
                        {
                            args = "--type nca --ncatype meta --titletype application --programnca \"" + txt_program_nca.Text + "\" --controlnca \"" + txt_control_nca.Text + "\" ";
                            if (txt_data_nca.Text != string.Empty)
                                args += "--datanca \"" + txt_data_nca.Text + "\" ";
                            if (txt_legalinfo_nca.Text != string.Empty)
                                args += "--legalnca \"" + txt_legalinfo_nca.Text + "\" ";
                            if (txt_htmldocument_nca.Text != string.Empty)
                                args += "--htmldocnca \"" + txt_htmldocument_nca.Text + "\"";
                            launch_hacpack(args);
                        }
                        break;
                    case "AddOnContent":
                        if (txt_cnmt.Text != string.Empty)
                        {
                            args = "--type nca --ncatype meta --titletype addon --cnmt \"" + txt_cnmt.Text + "\"";
                            launch_hacpack(args);
                        }
                        else if (rb_build_from_cnmt.IsChecked == true)
                            System.Windows.MessageBox.Show("CNMT path is empty", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        else if (txt_publicdata_nca.Text != string.Empty)
                        {
                            args = "--type nca --ncatype meta --titletype addon --publicdatanca \"" + txt_publicdata_nca.Text + "\"";
                            launch_hacpack(args);
                        }
                        else
                            System.Windows.MessageBox.Show("PublicData NCA path is empty", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        break;
                    case "SystemProgram":
                        if (txt_cnmt.Text != string.Empty)
                        {
                            args = "--type nca --ncatype meta --titletype systemprogram --cnmt \"" + txt_cnmt.Text + "\"";
                            launch_hacpack(args);
                        }
                        else if (rb_build_from_cnmt.IsChecked == true)
                            System.Windows.MessageBox.Show("CNMT path is empty", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        else if (txt_program_nca.Text != string.Empty)
                        {
                            args = "--type nca --ncatype meta --titletype systemprogram --programnca \"" + txt_program_nca.Text + "\"";
                            launch_hacpack(args);
                        }
                        else
                            System.Windows.MessageBox.Show("Program NCA path is empty", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        break;
                    case "SystemData":
                        if (txt_cnmt.Text != string.Empty)
                        {
                            args = "--type nca --ncatype meta --titletype systemdata --cnmt \"" + txt_cnmt.Text + "\"";
                            launch_hacpack(args);
                        }
                        else if (rb_build_from_cnmt.IsChecked == true)
                            System.Windows.MessageBox.Show("CNMT path is empty", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        else if (txt_data_nca.Text != string.Empty)
                        {
                            args = "--type nca --ncatype meta --titletype systemdata --datanca \"" + txt_data_nca.Text + "\"";
                            launch_hacpack(args);
                        }
                        else
                            System.Windows.MessageBox.Show("Data NCA path is empty", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        break;
                }
            }
        }

        private void btn_build_nsp_Click(object sender, RoutedEventArgs e)
        {
            if (txt_outdir.Text.ToLower().Contains("4n"))
            {
                System.Windows.MessageBox.Show("Johny Mode Activated", "Meme", MessageBoxButton.OK, MessageBoxImage.Warning);
                System.Windows.MessageBox.Show("ACT 3", "Meme", MessageBoxButton.OK, MessageBoxImage.Information);
                System.Windows.MessageBox.Show("Johny, Johny", "Papa", MessageBoxButton.OK, MessageBoxImage.Information);
                System.Windows.MessageBox.Show("Yes, Papa?", "Johny", MessageBoxButton.OK, MessageBoxImage.Information);
                System.Windows.MessageBox.Show("Playing a pirate game?", "Papa", MessageBoxButton.OK, MessageBoxImage.Information);
                System.Windows.MessageBox.Show("No, Papa", "Johny", MessageBoxButton.OK, MessageBoxImage.Information);
                System.Windows.MessageBox.Show("Telling lies?", "Papa", MessageBoxButton.OK, MessageBoxImage.Information);
                System.Windows.MessageBox.Show("No, Papa", "Johny", MessageBoxButton.OK, MessageBoxImage.Information);
                System.Windows.MessageBox.Show("Show me your gamecard", "Papa", MessageBoxButton.OK, MessageBoxImage.Information);
                System.Windows.MessageBox.Show("I'm backup loading you idiot...", "Johny", MessageBoxButton.OK, MessageBoxImage.Error);
            } else
            {
                txt_log.Text = string.Empty;
                if (txt_ncadir.Text == string.Empty)
                    System.Windows.MessageBox.Show("NCA directory path is empty", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                else if (txt_ncadir.Text == txt_outdir.Text)
                {
                    System.Windows.MessageBox.Show("Output directory and NCA directory are the same", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                else
                {
                    string args;
                    args = "--type nsp --ncadir \"" + txt_ncadir.Text + "\"";
                    launch_hacpack(args);
                }
            }
            
        }

        private void rb_build_from_nca_Checked(object sender, RoutedEventArgs e)
        {
            btn_browse_cnmt.IsEnabled = false;
            txt_cnmt.IsEnabled = false;
            txt_cnmt.Text = string.Empty;
            cmb_title_type.SelectedIndex = 0;
        }

        private void rb_build_from_cnmt_Checked(object sender, RoutedEventArgs e)
        {
            txt_program_nca.IsEnabled = false;
            txt_program_nca.Text = string.Empty;
            btn_browse_program_nca.IsEnabled = false;
            txt_control_nca.IsEnabled = false;
            txt_control_nca.Text = string.Empty;
            btn_browse_control_nca.IsEnabled = false;
            txt_legalinfo_nca.IsEnabled = false;
            txt_legalinfo_nca.Text = string.Empty;
            btn_browse_legalinfo_nca.IsEnabled = false;
            txt_htmldocument_nca.IsEnabled = false;
            txt_htmldocument_nca.Text = string.Empty;
            btn_browse_htmldocument_nca.IsEnabled = false;
            txt_data_nca.IsEnabled = false;
            txt_data_nca.Text = string.Empty;
            btn_browse_data_nca.IsEnabled = false;
            txt_publicdata_nca.IsEnabled = false;
            txt_publicdata_nca.Text = string.Empty;
            btn_browse_public_data.IsEnabled = false;
            btn_browse_cnmt.IsEnabled = true;
            txt_cnmt.IsEnabled = true;
            txt_cnmt.Text = string.Empty;
        }
    }
}
