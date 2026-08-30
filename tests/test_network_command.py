import io
import unittest
from contextlib import redirect_stdout

from blackline.cli.commands.network import network_cmd
from blackline.cli.commands.network.network_cmd import ExternalNetworkInfo, LocalNetworkInfo


class NetworkCommandTests(unittest.TestCase):
    def test_network_command_renders_sections(self):
        original_local = network_cmd.get_local_network_info
        original_external = network_cmd.get_external_network_info
        network_cmd.get_local_network_info = lambda: LocalNetworkInfo(
            ip="192.168.1.42",
            gateway="192.168.1.1",
            interface="wlan0",
        )
        network_cmd.get_external_network_info = lambda: ExternalNetworkInfo(
            ip="185.xxx.xxx.xxx",
            asn="AS9009 M247 Europe",
            location="NL",
        )
        output = io.StringIO()

        try:
            with redirect_stdout(output):
                network_cmd.handle_network(use_color=False)
        finally:
            network_cmd.get_local_network_info = original_local
            network_cmd.get_external_network_info = original_external

        text = output.getvalue()
        self.assertIn("[network]", text)
        self.assertIn("[local]", text)
        self.assertIn("ip        : 192.168.1.42", text)
        self.assertIn("gateway   : 192.168.1.1", text)
        self.assertIn("interface : wlan0", text)
        self.assertIn("[external]", text)
        self.assertIn("ip       : 185.xxx.xxx.xxx", text)
        self.assertIn("asn      : AS9009 M247 Europe", text)
        self.assertIn("location : NL", text)


if __name__ == "__main__":
    unittest.main()
