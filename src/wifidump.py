#!/usr/bin/env python
import errno
import sys
import traceback
import sqlite3
conn = sqlite3.connect('beacons.db')
from printer import Printer
from we import WirelessExtension
from optparse import OptionParser
class WifiDumpOptions:
    """A collection of options to control how the script runs"""
    def __init__(self):
        self.iface = 'mon0'
        self.channel = -1
        self.channel_hop = True
        self.max_channel = -1
        self.timeout = 5

    @staticmethod
    def create_options():
        """A class factory which parses command line options and returns an options instance"""
        parser = OptionParser()
        parser.add_option('-i', '--iface', dest='iface', default='mon0',
                          help='Interface to bind to')
        parser.add_option('-t', '--timeout', dest='timeout', default=5, type='int',
                          help='Timeout for the channel hop')
        parser.add_option('-c', '--channel', dest='channel', default=-1, type='int',
                          help='Channel to bind to')
        parser.add_option('--max-channel', dest='max_channel', default=-1, type='int',
                          help='Maximum channel number')
        options, _ = parser.parse_args()

        dump_options = WifiDumpOptions()
        dump_options.iface = options.iface
        dump_options.we = WirelessExtension(dump_options.iface)
        dump_options.timeout = options.timeout
        dump_options.channel = options.channel
        dump_options.channel_hop = (-1 == options.channel)
        dump_options.max_channel = options.max_channel
        if -1 == dump_options.max_channel:
            try:
                dump_options.max_channel = dump_options.we.get_max_channel()
                Printer.verbose('CHAN: max_channel[{0}]'.format(dump_options.max_channel), verbose_level=1)
            except Exception, e:
                Printer.exception(e)
                raise

        return dump_options

from scapy.all import sniff
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import Dot11Auth
from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.dot11 import Dot11ProbeReq
from scapy.layers.dot11 import Dot11ProbeResp
from scapy.layers.dot11 import RadioTap
import scapy_ex
class WifiScanner:
    def __init__(self, options):
        self.options = options
        self.listeners = []

    def attach(self, listener):
        if not listener in self.listeners:
            self.listeners.append(listener)

    def detach(self, listener):
        try:
            self.listeners.remove(listener)
        except ValueError:
            pass

    def notify(self, packet, modifier=None):
        for listener in self.listeners:
            if modifier != listener:
                listener.update(packet)
    
    def apply_filter(self, packet):
        try:
            # Verify the RadioTap header, scanner, and WE all match
            # if packet.haslayer(RadioTap) and not self.options.input_file:
                # assert (self.options.channel == packet[RadioTap].Channel), 'got[{0}] expect[{1}]'.format(packet[RadioTap].Channel, self.options.channel)

                # channel = self.options.we.get_channel()
                # assert (self.options.channel == channel), 'got[{0}] expected[{1}]'.format(channel, self.options.channel)

            # Track AP and STA
            if packet.haslayer(Dot11):
                self.notify(packet)
                return True

            # That's unexpected.  print for debugging
            else:
                Printer.error(packet.show())
        except Exception, exc:
            Printer.exception(exc)
        finally:
            return False

    def do_scan(self):
        sniff(iface=self.options.iface,
              store=False,
              lfilter=self.apply_filter)

    def scan(self):
        while True:
            try:
                
                if not self.do_scan():
                    break

            # Exit the scan on a keyboard break
            except KeyboardInterrupt:
                break

            # Curses generates system interupt exception (EINTR) when the window is resized
            except Exception, e:
                if e.args and e.args[0] == errno.EINTR:
                    pass
                else:
                    Printer.exception(e)
                    raise

class ConsolePrinter:
    def update(self, packet):
        c = conn.cursor()

        c.execute("INSERT INTO frames (mac, ap_mac, type, signal, ssid) VALUES (\"%s\", \"%s\", \"%s\", \"%s\", \"%s\")" % (packet[Dot11].addr1, packet[Dot11].addr2,
                                            packet[Dot11].type,
                                            packet[RadioTap].dBm_AntSignal,
                                            packet[Dot11].essid()
                                            ))
	conn.commit();
        Printer.write("%s > %s type:%2.2s/%2.2s signal/antenna:%4.4s/%s (%s)" % (packet[Dot11].addr2, packet[Dot11].addr1, 
                                            packet[Dot11].type, packet[Dot11].subtype, 
                                            packet[RadioTap].dBm_AntSignal, packet[RadioTap].Antenna,
                                            packet[Dot11].essid()))
        
def main():

    try:
        options = WifiDumpOptions.create_options()
        scanner = WifiScanner(options)
        scanner.attach(ConsolePrinter())

        try:
            scanner.scan()
        except Exception, e:
            Printer.exception(e)

    except Exception, e:
        sys.stderr.write(repr(e))
        traceback.print_exc(file=sys.stderr)


if __name__ == '__main__':
    main()
