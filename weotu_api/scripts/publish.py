#! /usr/bin/env python
# -*- coding: utf-8 -*-


# Weotu -- Accounts & authentication API
# By: Emmanuel Raviart <emmanuel@raviart.com>
#
# Copyright (C) 2014 Emmanuel Raviart
# https://gitorious.org/weotu
#
# This file is part of Weotu.
#
# Weotu is free software; you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# Weotu is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


"""0MQ gateway that receives data from a PULL socket and broadcasts it to a PUB socket."""


import argparse
import ConfigParser
import logging
import os
import sys

from biryani1 import baseconv, custom_conv, states
import zmq


app_name = os.path.splitext(os.path.basename(__file__))[0]
conv = custom_conv(baseconv, states)
log = logging.getLogger(app_name)
zmq_context = zmq.Context()


def main():
    parser = argparse.ArgumentParser(description = __doc__)
    parser.add_argument('config', help = 'path of configuration file')
    parser.add_argument('-v', '--verbose', action = 'store_true', default = False, help = "increase output verbosity")
    args = parser.parse_args()
    logging.basicConfig(level = logging.DEBUG if args.verbose else logging.WARNING, stream = sys.stdout)

    config_parser = ConfigParser.SafeConfigParser(dict(
        here = os.path.dirname(os.path.abspath(os.path.normpath(args.config))),
        ))
    config_parser.read(args.config)
    conf = conv.check(conv.pipe(
        conv.test_isinstance(dict),
        conv.struct(
            {
                'zmq_pub_socket': conv.not_none,
                'zmq_pull_socket': conv.not_none,
                },
            default = 'drop',
            ),
        conv.not_none,
        ))(dict(config_parser.items(app_name)), state = conv.default_state)

    zmq_receiver = zmq_context.socket(zmq.PULL)
    zmq_receiver.bind(conf['zmq_pull_socket'])
    zmq_publisher = zmq_context.socket(zmq.PUB)
    zmq_publisher.bind(conf['zmq_pub_socket'])

    while True:
        address, content = zmq_receiver.recv_multipart()
        log.info('{} {}'.format(address, content))
        zmq_publisher.send_multipart([address, content])

    return 0


if __name__ == "__main__":
    sys.exit(main())
