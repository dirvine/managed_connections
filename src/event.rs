// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net
// Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3,
// depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project
// generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.
// This, along with the
// Licenses can be found in the root directory of this project at LICENSE,
// COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network
// Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
// OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions
// and limitations
// relating to use of the SAFE Network Software.

use std::net;
use std::sync::mpsc;
use std::io;
use static_contact_info::StaticContactInfo;
use nat_traversal::{PrivRendezvousInfo, PubRendezvousInfo};
use peer_connection_type::PeerConnectionType;

/// The result of a `Service::prepare_contact_info` call.
#[derive(Debug)]
pub struct ConnectionInfoResult {
    /// The token that was passed to `prepare_connection_info`.
    pub result_token: u32,
    /// The new contact info, if successful.
    pub result: io::Result<OurConnectionInfo>,
}

/// Contact info generated by a call to `Service::prepare_contact_info`.
#[derive(Debug)]
pub struct OurConnectionInfo {
    info: PubRendezvousInfo,
    priv_info: PrivRendezvousInfo,
    // raii_tcp_acceptor: RaiiTcpAcceptor,
    // tcp_addrs: Vec<SocketAddr>,
    udp_socket: net::UdpSocket,
    static_contact_info: StaticContactInfo,
}

impl OurConnectionInfo {
    /// Convert our connection info to theirs so that we can give it to peer.
    pub fn to_their_connection_info(&self) -> TheirConnectionInfo {
        TheirConnectionInfo {
            info: self.info.clone(),
            static_contact_info: self.static_contact_info.clone(), /* tcp_addrs:
                                                                    * self.tcp_addrs.clone(), */
        }
    }
}

/// Contact info used to connect to another peer.
#[derive(Debug, RustcEncodable, RustcDecodable)]
pub struct TheirConnectionInfo {
    info: PubRendezvousInfo,
    static_contact_info: StaticContactInfo,
}



/// Enum representing different events that will be sent over the asynchronous channel to the user
/// of this module.
#[derive(Debug)]
pub enum Event {
    /// Invoked when a new message is received.  Passes the message.
    NewMessage(usize, Vec<u8>),
    /// Invoked when a connection to a new peer is established.
    NewPeer(usize, PeerConnectionType),
    /// Invoked when a peer is lost.
    LostPeer(usize),
    /// Raised once the list of bootstrap contacts is exhausted.
    BootstrapFinished,
    /// Invoked as a result to the call of `Service::prepare_contact_info`.
    ConnectionInfoPrepared(ConnectionInfoResult),
}
