use bytes::Bytes;

use ring::signature::Ed25519KeyPair;

use tun_tap::Mode;

use untrusted::Input;

use std::net::SocketAddr;
use std::io::{Error, Read};
use std::fs::File;



#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum FileOrValue {
    File {
        file: String,
        #[serde(default)]
        #[serde(skip)]
        cache: Option<Bytes>,
    },
    Value {
        value: String,
        #[serde(default)]
        #[serde(skip)]
        cache: Option<Bytes>,
    },
}

impl FileOrValue {
    pub fn load(&mut self) -> Result<(), Error> {
        let val = self.get_value()?;

        match *self {
            FileOrValue::File { file: _, ref mut cache } => {
                *cache = Some(val);
            }

            FileOrValue::Value { value: _, ref mut cache } => {
                *cache = Some(val);
            }
        }

        Ok(())
    }

    pub fn get_value(&self) -> Result<Bytes, Error> {
        match *self {
            FileOrValue::Value { ref value, ref cache } => {
                Ok(if let Some(ref cache) = cache {
                    cache.clone()
                } else {
                    Bytes::from(value.clone().into_bytes())
                })
            }

            FileOrValue::File { ref file, ref cache } => {
                if let Some(ref cache) = cache {
                    return Ok(cache.clone());
                }

                let mut fd = File::open(file)?;
                let mut contents = Vec::new();
                fd.read_to_end(&mut contents)?;
                let contents = Bytes::from(contents);
                Ok(contents)
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub key: FileOrValue,
    #[serde(skip)]
    #[serde(default)]
    public_key: Bytes,
    #[serde(default)]
    #[serde(skip)]
    cached_network_id: Option<Bytes>,
    #[serde(rename = "network-id")]
    pub network_id: String,
    #[serde(default)]
    pub server: ServerConfig,
    pub auth: AuthConfig,
    #[serde(rename = "network")]
    #[serde(default)]
    pub networks: Vec<NetworkConfig>,
    #[serde(default)]
    pub interface: InterfaceConfig,
    #[serde(default)]
    pub router: RouterConfig,
}

impl Config {
    pub fn get_public_key(&self) -> Bytes {
        return self.public_key.clone()
    }

    pub fn get_key_pair(&self) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(Input::from(&self.key.get_value().unwrap())).unwrap()
    }

    pub fn load(&mut self) -> Result<(), Error> {
        self.public_key = Bytes::from(self.get_key_pair().public_key_bytes());
        self.cached_network_id = Some(self.get_network_id());
        self.auth.load()?;
        self.key.load()?;

        Ok(())
    }

    pub fn get_network_id(&self) -> Bytes {
        if let Some(ref cache) = self.cached_network_id {
            cache.clone()
        } else {
            Bytes::from(self.network_id.clone().into_bytes())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "ServerConfig::default_threads")]
    pub threads: u8
}

impl ServerConfig {
    fn default_threads() -> u8 { 2 }
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            threads: ServerConfig::default_threads()
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum NetworkConfig {
    #[serde(rename = "dns")]
    DnsNetworkConfig(DnsNetworkConfig),
    #[serde(rename = "peers")]
    PeersNetworkConfig(PeersNetworkConfig),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DnsNetworkConfig {
    pub domain: String
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PeersNetworkConfig {
    #[serde(default)]
    pub peers: Vec<SocketAddr>
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InterfaceConfig {
    #[serde(default = "InterfaceConfig::default_mode")]
    pub mode: InterfaceConfigMode,
    #[serde(default = "InterfaceConfig::default_name")]
    pub name: String,
    #[serde(default = "InterfaceConfig::default_mtu")]
    pub mtu: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, Ord, PartialOrd, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceConfigMode {
    Tap,
    Tun,
}

impl From<InterfaceConfigMode> for Mode {
    fn from(mode: InterfaceConfigMode) -> Self {
        match mode {
            InterfaceConfigMode::Tap => Mode::Tap,
            InterfaceConfigMode::Tun => Mode::Tun,
        }
    }
}

impl InterfaceConfig {
    fn default_name() -> String { "bw%d".to_string() }
    fn default_mtu() -> u32 { 1400 }
    fn default_mode() -> InterfaceConfigMode { InterfaceConfigMode::Tap }
}

impl Default for InterfaceConfig {
    fn default() -> Self {
        InterfaceConfig {
            mode: InterfaceConfig::default_mode(),
            name: InterfaceConfig::default_name(),
            mtu: InterfaceConfig::default_mtu(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum AuthConfig {
    SharedSecretConfig(SharedSecretConfig),
    CertificateAuthorityConfig(CertificateAuthorityConfig),
}

impl AuthConfig {
    pub fn load(&mut self) -> Result<(), Error> {
        match self {
            AuthConfig::CertificateAuthorityConfig(ref mut c) => c.load()?,
            AuthConfig::SharedSecretConfig(ref mut c) => c.load()?,
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CertificateAuthorityConfig {
    pub signature: FileOrValue,
    pub ca: FileOrValue,
}

impl CertificateAuthorityConfig {
    pub fn load(&mut self) -> Result<(), Error> {
        self.signature.load()?;
        self.ca.load()?;

        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SharedSecretConfig {
    #[serde(skip, default)]
    cache: Option<Bytes>,
    pub secret: String,
}

impl SharedSecretConfig {
    pub fn load(&mut self) -> Result<(), Error> {
        self.cache = Some(self.get_secret());

        Ok(())
    }

    pub fn get_secret(&self) -> Bytes {
        if let Some(ref cache) = self.cache {
            cache.clone()
        } else {
            Bytes::from(self.secret.clone().into_bytes())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RouterConfig {
    #[serde(default = "RouterConfig::default_name")]
    pub name: RouterChoice,
    #[cfg(feature = "python-router")]
    #[serde(default = "RouterConfig::default_python")]
    pub python: Option<PythonRouterConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RouterChoice {
    Dumb,
    #[cfg(feature = "python-router")]
    Python,
}

impl RouterConfig {
    fn default_name() -> RouterChoice { RouterChoice::Dumb }
    #[cfg(feature = "python-router")]
    fn default_python() -> Option<PythonRouterConfig> { None }
}

impl Default for RouterConfig {
    fn default() -> Self {
        RouterConfig {
            name: RouterConfig::default_name(),
            #[cfg(feature = "python-router")]
            python: None,
        }
    }
}

#[cfg(feature = "python-router")]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PythonRouterConfig {
    pub script: String,
}

#[cfg(test)]
mod test {
    use toml;
    use super::Config;

    #[test]
    fn test_parsing() {
        let config: Config = toml::from_str(r#"
key = { file = "12345678901234567890123456789012" }

[server]
threads = 4

[[network]]
type = "dns"
domain = "zer.ooo"

[[network]]
type = "peers"
peers = [
  "1.2.3.4:124"
]

[interface]
mtu = 1400
name = "bw%d"
mode = "tap"

[auth]
secret = "help"

[router]
name = "dumb"

    [router.python]
    script = "python/example_router.py"
"#).unwrap();
        assert_eq!(config.networks.len(), 2);
        assert_eq!(config.server.threads, 4);
    }
}