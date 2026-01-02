//! Абстракции сетевого стека и реализация на базе smoltcp.
use crate::error::IdentityError;

/// Унифицированный IPv4 эндпоинт.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkEndpoint {
    pub addr: [u8; 4],
    pub port: u16,
}

impl NetworkEndpoint {
    pub const fn ipv4(addr: [u8; 4], port: u16) -> Self {
        Self { addr, port }
    }
}

/// Ошибки сетевого стека.
#[derive(Debug, Clone, Copy)]
pub enum NetworkError {
    /// Стек недоступен или не инициализирован.
    Unavailable,
    /// Буфер переполнен или окно слишком маленькое.
    BufferExhausted,
    /// Порт или адрес некорректны.
    InvalidEndpoint,
    /// TCP-соединение закрыто.
    ConnectionClosed,
}

impl From<NetworkError> for IdentityError {
    fn from(value: NetworkError) -> Self {
        match value {
            NetworkError::Unavailable => IdentityError::NetworkUnavailable,
            _ => IdentityError::NetworkStackError,
        }
    }
}

/// Минимальный интерфейс для UDP/TCP транспорта.
pub trait NetworkStack {
    fn poll(&mut self, now_ms: i64) -> Result<(), NetworkError>;
    fn send_udp(&mut self, endpoint: NetworkEndpoint, payload: &[u8]) -> Result<(), NetworkError>;
    fn recv_udp(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<Option<(usize, NetworkEndpoint)>, NetworkError>;
    fn connect_tcp(&mut self, endpoint: NetworkEndpoint) -> Result<(), NetworkError>;
    fn send_tcp(&mut self, data: &[u8]) -> Result<(), NetworkError>;
    fn recv_tcp(&mut self, buffer: &mut [u8]) -> Result<usize, NetworkError>;
}

/// Заглушка для устройств без сети.
#[derive(Default)]
pub struct NullNetwork;

impl NetworkStack for NullNetwork {
    fn poll(&mut self, _now_ms: i64) -> Result<(), NetworkError> {
        Ok(())
    }

    fn send_udp(
        &mut self,
        _endpoint: NetworkEndpoint,
        _payload: &[u8],
    ) -> Result<(), NetworkError> {
        Err(NetworkError::Unavailable)
    }

    fn recv_udp(
        &mut self,
        _buffer: &mut [u8],
    ) -> Result<Option<(usize, NetworkEndpoint)>, NetworkError> {
        Ok(None)
    }

    fn connect_tcp(&mut self, _endpoint: NetworkEndpoint) -> Result<(), NetworkError> {
        Err(NetworkError::Unavailable)
    }

    fn send_tcp(&mut self, _data: &[u8]) -> Result<(), NetworkError> {
        Err(NetworkError::Unavailable)
    }

    fn recv_tcp(&mut self, _buffer: &mut [u8]) -> Result<usize, NetworkError> {
        Err(NetworkError::Unavailable)
    }
}

#[cfg(feature = "network")]
mod smoltcp_backend {
    use alloc::vec::Vec;

    use managed::ManagedSlice;
    use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
    use smoltcp::phy::Loopback;
    use smoltcp::socket::{tcp, udp};
    use smoltcp::time::Instant;
    use smoltcp::wire::{
        EthernetAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address,
    };

    use super::{NetworkEndpoint, NetworkError, NetworkStack};

    /// Конфигурация сетевого стека.
    #[derive(Clone)]
    pub struct NetworkConfig {
        pub mac: [u8; 6],
        pub ipv4_addr: [u8; 4],
        pub ipv4_prefix: u8,
        pub udp_port: u16,
        pub tcp_port: u16,
        pub udp_depth: usize,
        pub tcp_rx: usize,
        pub tcp_tx: usize,
        pub mtu: usize,
        pub random_seed: u64,
    }

    impl Default for NetworkConfig {
        fn default() -> Self {
            Self {
                mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
                ipv4_addr: [192, 168, 4, 1],
                ipv4_prefix: 24,
                udp_port: 7,
                tcp_port: 8022,
                udp_depth: 4,
                tcp_rx: 1024,
                tcp_tx: 1024,
                mtu: 1536,
                random_seed: 0xA5A5_1337_DEAD_BEEF,
            }
        }
    }

    /// Сетевой стек поверх smoltcp + Loopback (можно заменить на драйвер MAC).
    pub struct SmoltcpNetwork {
        iface: Interface<'static, Loopback>,
        device: Loopback,
        sockets: SocketSet<'static>,
        udp_handle: SocketHandle,
        tcp_handle: SocketHandle,
        ipv4: IpAddress,
        udp_port: u16,
        tcp_port: u16,
    }

    impl SmoltcpNetwork {
        pub fn new(config: NetworkConfig) -> Self {
            let mut device = Loopback::new(config.mtu);
            let hw_addr = EthernetAddress(config.mac);
            let mut iface_config = IfaceConfig::new(hw_addr.into());
            iface_config.random_seed = config.random_seed;

            let mut iface = Interface::new(iface_config, &mut device, Instant::from_millis(0));
            let ipv4 = IpAddress::Ipv4(Ipv4Address::from_bytes(&config.ipv4_addr));
            iface.update_ip_addrs(|addrs| {
                let cidr = IpCidr::new(ipv4, config.ipv4_prefix);
                if let Err(err) = addrs.push(cidr) {
                    panic!("failed to set IP address: {:?}", err);
                }
            });

            let udp_socket = {
                let rx_meta = vec![udp::PacketMetadata::EMPTY; config.udp_depth];
                let tx_meta = vec![udp::PacketMetadata::EMPTY; config.udp_depth];
                let rx_buf = vec![0u8; config.mtu * config.udp_depth];
                let tx_buf = vec![0u8; config.mtu * config.udp_depth];
                let rx_buffer = udp::PacketBuffer::new(
                    ManagedSlice::Owned(rx_meta),
                    ManagedSlice::Owned(rx_buf),
                );
                let tx_buffer = udp::PacketBuffer::new(
                    ManagedSlice::Owned(tx_meta),
                    ManagedSlice::Owned(tx_buf),
                );
                udp::Socket::new(rx_buffer, tx_buffer)
            };

            let tcp_socket = {
                let rx_buffer =
                    tcp::SocketBuffer::new(ManagedSlice::Owned(vec![0u8; config.tcp_rx]));
                let tx_buffer =
                    tcp::SocketBuffer::new(ManagedSlice::Owned(vec![0u8; config.tcp_tx]));
                tcp::Socket::new(rx_buffer, tx_buffer)
            };

            let mut sockets = SocketSet::new(Vec::new());
            let udp_handle = sockets.add(udp_socket);
            let tcp_handle = sockets.add(tcp_socket);

            Self {
                iface,
                device,
                sockets,
                udp_handle,
                tcp_handle,
                ipv4,
                udp_port: config.udp_port,
                tcp_port: config.tcp_port,
            }
        }

        fn endpoint_to_ip(ep: NetworkEndpoint) -> IpEndpoint {
            IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::from_bytes(&ep.addr)), ep.port)
        }
    }

    impl NetworkStack for SmoltcpNetwork {
        fn poll(&mut self, now_ms: i64) -> Result<(), NetworkError> {
            let timestamp = Instant::from_millis(now_ms);
            self.iface
                .poll(timestamp, &mut self.device, &mut self.sockets);
            Ok(())
        }

        fn send_udp(
            &mut self,
            endpoint: NetworkEndpoint,
            payload: &[u8],
        ) -> Result<(), NetworkError> {
            let socket = self.sockets.get_mut::<udp::Socket>(self.udp_handle);
            if !socket.is_open() {
                socket
                    .bind((self.udp_port).into())
                    .map_err(|_| NetworkError::InvalidEndpoint)?;
            }
            socket
                .send_slice(payload, Self::endpoint_to_ip(endpoint))
                .map_err(|_| NetworkError::BufferExhausted)?;
            Ok(())
        }

        fn recv_udp(
            &mut self,
            buffer: &mut [u8],
        ) -> Result<Option<(usize, NetworkEndpoint)>, NetworkError> {
            let socket = self.sockets.get_mut::<udp::Socket>(self.udp_handle);
            match socket.recv_slice(buffer) {
                Ok((len, meta)) => {
                    let addr = match meta.endpoint.addr {
                        IpAddress::Ipv4(v4) => v4.octets(),
                        _ => return Err(NetworkError::InvalidEndpoint),
                    };
                    Ok(Some((len, NetworkEndpoint::ipv4(addr, meta.endpoint.port))))
                }
                Err(udp::RecvError::Exhausted) => Ok(None),
                Err(udp::RecvError::Truncated) => Err(NetworkError::BufferExhausted),
            }
        }

        fn connect_tcp(&mut self, endpoint: NetworkEndpoint) -> Result<(), NetworkError> {
            let socket = self.sockets.get_mut::<tcp::Socket>(self.tcp_handle);
            let local = IpListenEndpoint {
                addr: Some(self.ipv4),
                port: self.tcp_port,
            };
            socket
                .connect(self.iface.context(), Self::endpoint_to_ip(endpoint), local)
                .map_err(|_| NetworkError::InvalidEndpoint)
        }

        fn send_tcp(&mut self, data: &[u8]) -> Result<(), NetworkError> {
            let socket = self.sockets.get_mut::<tcp::Socket>(self.tcp_handle);
            socket
                .send_slice(data)
                .map(|_| ())
                .map_err(|_| NetworkError::BufferExhausted)
        }

        fn recv_tcp(&mut self, buffer: &mut [u8]) -> Result<usize, NetworkError> {
            let socket = self.sockets.get_mut::<tcp::Socket>(self.tcp_handle);
            socket.recv_slice(buffer).map_err(|err| match err {
                tcp::RecvError::Finished => NetworkError::ConnectionClosed,
                _ => NetworkError::BufferExhausted,
            })
        }
    }
}

#[cfg(feature = "network")]
pub use smoltcp_backend::{NetworkConfig, SmoltcpNetwork};
