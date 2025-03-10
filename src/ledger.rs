use {
    crate::remote_wallet::{RemoteWallet, RemoteWalletInfo},
    console::Emoji,
    dialoguer::{theme::ColorfulTheme, Select},
    semver::Version as FirmwareVersion,
    std::str::FromStr,
    std::{fmt, rc::Rc},
};
#[cfg(feature = "hidapi")]
use {
    crate::{ledger_error::LedgerError, locator::Manufacturer},
    ed25519_dalek::{PublicKey, Signature, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH},
    log::*,
    num_traits::FromPrimitive,
    std::{cmp::min, convert::TryFrom},
};

use crate::remote_wallet::{RemoteWalletError, RemoteWalletManager};

static CHECK_MARK: Emoji = Emoji("✅ ", "");

const APDU_TAG: u8 = 0x05;
const APDU_CLA: u8 = 0xe0;
const APDU_PAYLOAD_HEADER_LEN: usize = 7;

const P1_NON_CONFIRM: u8 = 0x00;
const P1_CONFIRM: u8 = 0x01;
const P2_EXTEND: u8 = 0x01;
const P2_MORE: u8 = 0x02;
const MAX_CHUNK_SIZE: usize = 255;
const MAX_DATA_LEN: usize = 1024;

const APDU_SUCCESS_CODE: usize = 0x9000;

const HASH_SIZE: usize = 32;

/// Ledger vendor ID
const LEDGER_VID: u16 = 0x2c97;
/// Ledger product IDs
const LEDGER_NANO_S_PIDS: [u16; 33] = [
    0x0001, 0x1000, 0x1001, 0x1002, 0x1003, 0x1004, 0x1005, 0x1006, 0x1007, 0x1008, 0x1009, 0x100a,
    0x100b, 0x100c, 0x100d, 0x100e, 0x100f, 0x1010, 0x1011, 0x1012, 0x1013, 0x1014, 0x1015, 0x1016,
    0x1017, 0x1018, 0x1019, 0x101a, 0x101b, 0x101c, 0x101d, 0x101e, 0x101f,
];
const LEDGER_NANO_X_PIDS: [u16; 33] = [
    0x0004, 0x4000, 0x4001, 0x4002, 0x4003, 0x4004, 0x4005, 0x4006, 0x4007, 0x4008, 0x4009, 0x400a,
    0x400b, 0x400c, 0x400d, 0x400e, 0x400f, 0x4010, 0x4011, 0x4012, 0x4013, 0x4014, 0x4015, 0x4016,
    0x4017, 0x4018, 0x4019, 0x401a, 0x401b, 0x401c, 0x401d, 0x401e, 0x401f,
];
const LEDGER_NANO_S_PLUS_PIDS: [u16; 33] = [
    0x0005, 0x5000, 0x5001, 0x5002, 0x5003, 0x5004, 0x5005, 0x5006, 0x5007, 0x5008, 0x5009, 0x500a,
    0x500b, 0x500c, 0x500d, 0x500e, 0x500f, 0x5010, 0x5011, 0x5012, 0x5013, 0x5014, 0x5015, 0x5016,
    0x5017, 0x5018, 0x5019, 0x501a, 0x501b, 0x501c, 0x501d, 0x501e, 0x501f,
];
const LEDGER_STAX_PIDS: [u16; 33] = [
    0x0006, 0x6000, 0x6001, 0x6002, 0x6003, 0x6004, 0x6005, 0x6006, 0x6007, 0x6008, 0x6009, 0x600a,
    0x600b, 0x600c, 0x600d, 0x600e, 0x600f, 0x6010, 0x6011, 0x6012, 0x6013, 0x6014, 0x6015, 0x6016,
    0x6017, 0x6018, 0x6019, 0x601a, 0x601b, 0x601c, 0x601d, 0x601e, 0x601f,
];
const LEDGER_FLEX_PIDS: [u16; 33] = [
    0x0007, 0x7000, 0x7001, 0x7002, 0x7003, 0x7004, 0x7005, 0x7006, 0x7007, 0x7008, 0x7009, 0x700a,
    0x700b, 0x700c, 0x700d, 0x700e, 0x700f, 0x7010, 0x7011, 0x7012, 0x7013, 0x7014, 0x7015, 0x7016,
    0x7017, 0x7018, 0x7019, 0x701a, 0x701b, 0x701c, 0x701d, 0x701e, 0x701f,
];
const LEDGER_TRANSPORT_HEADER_LEN: usize = 5;

const HID_PACKET_SIZE: usize = 64 + HID_PREFIX_ZERO;

#[cfg(windows)]
const HID_PREFIX_ZERO: usize = 1;
#[cfg(not(windows))]
const HID_PREFIX_ZERO: usize = 0;

mod commands {
    pub const GET_APP_CONFIGURATION: u8 = 0x01;
    pub const GET_PUBKEY: u8 = 0x02;
    pub const SIGN_MESSAGE: u8 = 0x03;
    pub const GET_ADDRESS: u8 = 0x04;
    pub const SIGN_TRANSACTION: u8 = 0x05;
}

pub const SIGN_MAGIC: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];

#[derive(Clone, Copy)]
pub enum WalletType {
    WalletV3 = 0,
    EverWallet = 1,
    SafeMultisig = 2,
    SafeMultisig24h = 3,
    SetcodeMultisig = 4,
    BridgeMultisig = 5,
    Surf = 6,
    Multisig2 = 7,
    Multisig2_1 = 8,
}

impl TryFrom<u32> for WalletType {
    type Error = anyhow::Error;

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(WalletType::WalletV3),
            1 => Ok(WalletType::EverWallet),
            2 => Ok(WalletType::SafeMultisig),
            3 => Ok(WalletType::SafeMultisig24h),
            4 => Ok(WalletType::SetcodeMultisig),
            5 => Ok(WalletType::BridgeMultisig),
            6 => Ok(WalletType::Surf),
            7 => Ok(WalletType::Multisig2),
            8 => Ok(WalletType::Multisig2_1),
            _ => anyhow::bail!("Unknown wallet type"),
        }
    }
}

impl FromStr for WalletType {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "WalletV3" => Ok(WalletType::WalletV3),
            "EverWallet" => Ok(WalletType::EverWallet),
            "SafeMultisig" => Ok(WalletType::SafeMultisig),
            "SafeMultisig24h" => Ok(WalletType::SafeMultisig24h),
            "SetcodeMultisig" => Ok(WalletType::SetcodeMultisig),
            "BridgeMultisig" => Ok(WalletType::BridgeMultisig),
            "Surf" => Ok(WalletType::Surf),
            "Multisig2" => Ok(WalletType::Multisig2),
            "Multisig2_1" => Ok(WalletType::Multisig2_1),
            _ => Err("Unknown wallet type".to_string()),
        }
    }
}

/// Ledger Wallet device
pub struct LedgerWallet {
    #[cfg(feature = "hidapi")]
    pub device: hidapi::HidDevice,
    pub pretty_path: String,
    pub version: FirmwareVersion,
}

impl fmt::Debug for LedgerWallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HidDevice")
    }
}

#[cfg(feature = "hidapi")]
impl LedgerWallet {
    pub fn new(device: hidapi::HidDevice) -> Self {
        Self {
            device,
            pretty_path: String::default(),
            version: FirmwareVersion::new(0, 0, 0),
        }
    }

    // Transport Protocol:
    //		* Communication Channel Id	(2 bytes big endian )
    //		* Command Tag				(1 byte)
    //		* Packet Sequence ID		(2 bytes big endian)
    //		* Payload				    (Optional)
    //
    // Payload
    //		* APDU Total Length		(2 bytes big endian)
    //		* APDU_CLA				(1 byte)
    //		* APDU_INS				(1 byte)
    //		* APDU_P1				(1 byte)
    //		* APDU_P2				(1 byte)
    //		* APDU_LENGTH 	        (1 byte)
    //		* APDU_Payload			(Variable)
    //
    fn write(&self, command: u8, p1: u8, p2: u8, data: &[u8]) -> Result<(), RemoteWalletError> {
        let data_len = data.len();
        let mut offset = 0;
        let mut sequence_number = 0;
        let mut hid_chunk = [0_u8; HID_PACKET_SIZE];

        while sequence_number == 0 || offset < data_len {
            let header = if sequence_number == 0 {
                LEDGER_TRANSPORT_HEADER_LEN + APDU_PAYLOAD_HEADER_LEN
            } else {
                LEDGER_TRANSPORT_HEADER_LEN
            };
            let size = min(64 - header, data_len - offset);
            {
                let chunk = &mut hid_chunk[HID_PREFIX_ZERO..];
                chunk[0..5].copy_from_slice(&[
                    0x01,
                    0x01,
                    APDU_TAG,
                    (sequence_number >> 8) as u8,
                    (sequence_number & 0xff) as u8,
                ]);

                if sequence_number == 0 {
                    let data_len = data.len() + 5;
                    chunk[5..12].copy_from_slice(&[
                        (data_len >> 8) as u8,
                        (data_len & 0xff) as u8,
                        APDU_CLA,
                        command,
                        p1,
                        p2,
                        data.len() as u8,
                    ]);
                }

                chunk[header..header + size].copy_from_slice(&data[offset..offset + size]);
            }
            trace!("Ledger write {:?}", &hid_chunk[..]);
            let n = self.device.write(&hid_chunk[..])?;
            if n < size + header {
                return Err(RemoteWalletError::Protocol("Write data size mismatch"));
            }
            offset += size;
            sequence_number += 1;
            if sequence_number >= 0xffff {
                return Err(RemoteWalletError::Protocol(
                    "Maximum sequence number reached",
                ));
            }
        }

        Ok(())
    }

    // Transport Protocol:
    //		* Communication Channel Id		(2 bytes big endian )
    //		* Command Tag			        (1 byte)
    //		* Packet Sequence ID			(2 bytes big endian)
    //		* Payload				        (Optional)
    //
    // Payload
    //		* APDU_LENGTH				    (1 byte)
    //		* APDU_Payload				    (Variable)
    //
    fn read(&self) -> Result<Vec<u8>, RemoteWalletError> {
        let mut message_size = 0;
        let mut message = Vec::new();

        // terminate the loop if `sequence_number` reaches its max_value and report error
        for chunk_index in 0..=0xffff {
            let mut chunk: [u8; HID_PACKET_SIZE] = [0; HID_PACKET_SIZE];
            let chunk_size = self.device.read(&mut chunk)?;
            trace!("Ledger read {:?}", &chunk[..]);
            if chunk_size < LEDGER_TRANSPORT_HEADER_LEN
                || chunk[0] != 0x01
                || chunk[1] != 0x01
                || chunk[2] != APDU_TAG
            {
                return Err(RemoteWalletError::Protocol("Unexpected chunk header"));
            }
            let seq = ((chunk[3] as usize) << 8) | (chunk[4] as usize);
            if seq != chunk_index {
                return Err(RemoteWalletError::Protocol("Unexpected chunk header"));
            }

            let mut offset = 5;
            if seq == 0 {
                // Read message size and status word.
                if chunk_size < 7 {
                    return Err(RemoteWalletError::Protocol("Unexpected chunk header"));
                }
                message_size = ((chunk[5] as usize) << 8) | (chunk[6] as usize);
                offset += 2;
            }
            message.extend_from_slice(&chunk[offset..chunk_size]);
            message.truncate(message_size);
            if message.len() == message_size {
                break;
            }
        }
        if message.len() < 2 {
            return Err(RemoteWalletError::Protocol("No status word"));
        }
        let status =
            ((message[message.len() - 2] as usize) << 8) | (message[message.len() - 1] as usize);
        trace!("Read status {:x}", status);
        Self::parse_status(status)?;
        let new_len = message.len() - 2;
        message.truncate(new_len);
        Ok(message)
    }

    fn _send_apdu(
        &self,
        command: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> Result<Vec<u8>, RemoteWalletError> {
        self.write(command, p1, p2, data)?;
        if p1 == P1_CONFIRM && is_last_part(p2) {
            println!(
                "Waiting for your approval on {} {}",
                self.name(),
                self.pretty_path
            );
            let result = self.read()?;
            println!("{CHECK_MARK}Approved");
            Ok(result)
        } else {
            self.read()
        }
    }

    fn send_apdu(
        &self,
        command: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> Result<Vec<u8>, RemoteWalletError> {
        self._send_apdu(command, p1, p2, data)
    }

    fn get_firmware_version(&self) -> Result<FirmwareVersion, RemoteWalletError> {
        let config = self._send_apdu(commands::GET_APP_CONFIGURATION, P1_NON_CONFIRM, 0, &[])?;
        if config.len() != 3 {
            return Err(RemoteWalletError::Protocol("Version packet size mismatch"));
        }

        Ok(FirmwareVersion::new(
            config[0].into(),
            config[1].into(),
            config[2].into(),
        ))
    }

    fn parse_status(status: usize) -> Result<(), RemoteWalletError> {
        if status == APDU_SUCCESS_CODE {
            Ok(())
        } else if let Some(err) = LedgerError::from_usize(status) {
            Err(err.into())
        } else {
            Err(RemoteWalletError::Protocol("Unknown error"))
        }
    }
}

#[cfg(not(feature = "hidapi"))]
impl RemoteWallet<Self> for LedgerWallet {}
#[cfg(feature = "hidapi")]
impl RemoteWallet<hidapi::DeviceInfo> for LedgerWallet {
    fn name(&self) -> &str {
        "Ledger hardware wallet"
    }

    fn read_device(
        &mut self,
        dev_info: &hidapi::DeviceInfo,
    ) -> Result<RemoteWalletInfo, RemoteWalletError> {
        let manufacturer = dev_info
            .manufacturer_string()
            .and_then(|s| Manufacturer::try_from(s).ok())
            .unwrap_or_default();
        let model = dev_info
            .product_string()
            .unwrap_or("Unknown")
            .to_lowercase()
            .replace(' ', "-");
        let serial = dev_info.serial_number().unwrap_or("Unknown").to_string();
        let host_device_path = dev_info.path().to_string_lossy().to_string();
        let version = self.get_firmware_version()?;
        self.version = version;
        let pubkey_result = self.get_pubkey(u32::default(), false);
        let (pubkey, error) = match pubkey_result {
            Ok(pubkey) => (pubkey, None),
            Err(err) => (PublicKey::default(), Some(err)),
        };
        Ok(RemoteWalletInfo {
            model,
            manufacturer,
            serial,
            host_device_path,
            pubkey,
            error,
        })
    }

    fn get_pubkey(&self, account: u32, confirm_key: bool) -> Result<PublicKey, RemoteWalletError> {
        let data = account.to_be_bytes();

        let key = self.send_apdu(
            commands::GET_PUBKEY,
            if confirm_key {
                P1_CONFIRM
            } else {
                P1_NON_CONFIRM
            },
            0,
            &data,
        )?;
        if key.len() != PUBLIC_KEY_LENGTH + 1 {
            return Err(RemoteWalletError::Protocol("Key packet size mismatch"));
        }
        Ok(PublicKey::from_bytes(&key[1..])?)
    }

    fn sign_message(&self, account: u32, data: &[u8]) -> Result<Signature, RemoteWalletError> {
        if data.len() != HASH_SIZE {
            return Err(RemoteWalletError::InvalidInput(
                "Message hash to sign has invalid size".to_string(),
            ));
        }

        let mut payload = account.to_be_bytes().to_vec();

        payload.extend_from_slice(data);

        let result = self.send_apdu(commands::SIGN_MESSAGE, P1_CONFIRM, 0, &payload)?;

        if result.len() != SIGNATURE_LENGTH + 1 {
            return Err(RemoteWalletError::Protocol(
                "Signature packet size mismatch",
            ));
        }
        Ok(Signature::from_bytes(&result[1..])?)
    }

    fn get_address(
        &self,
        account: u32,
        wallet_type: WalletType,
        confirm_key: bool,
    ) -> Result<Vec<u8>, RemoteWalletError> {
        let mut data = account.to_be_bytes().to_vec();
        data.push(wallet_type as u8);

        let address = self.send_apdu(
            commands::GET_ADDRESS,
            if confirm_key {
                P1_CONFIRM
            } else {
                P1_NON_CONFIRM
            },
            0,
            &data,
        )?;

        if address.len() != HASH_SIZE + 1 {
            return Err(RemoteWalletError::Protocol("Address size mismatch"));
        }

        Ok(address[1..].to_vec())
    }

    fn sign_transaction(
        &self,
        account: u32,
        origin_wallet_type: WalletType,
        decimals: u8,
        ticker: &str,
        meta: SignTransactionMeta,
        data: &[u8],
    ) -> Result<Signature, RemoteWalletError> {
        if data.len() > MAX_DATA_LEN {
            return Err(RemoteWalletError::InvalidInput(
                "Message to sign is too long".to_string(),
            ));
        }

        // Strip BOC magic
        let data = match data.strip_prefix(&[0xB5, 0xEE, 0x9C, 0x72]) {
            Some(data) => data,
            None => {
                return Err(RemoteWalletError::InvalidInput(
                    "Unknown BOC tag".to_string(),
                ))
            }
        };

        let mut payload = account.to_be_bytes().to_vec();
        payload.extend_from_slice(&[origin_wallet_type as u8, decimals]);

        let ticker = ticker.as_bytes();
        payload.push(ticker.len() as u8);
        payload.extend_from_slice(ticker);

        let mut metadata: u8 = 0;
        if meta.current_wallet_type.is_some() {
            metadata |= 1;
        }
        if meta.workchain_id.is_some() {
            metadata |= 2;
        }
        if meta.chain_id.is_some() {
            metadata |= 8;
        }
        payload.push(metadata);

        if let Some(current_wallet_type) = meta.current_wallet_type {
            payload.push(current_wallet_type as u8);
        }

        if let Some(workchain_id) = meta.workchain_id {
            payload.push(workchain_id);
        }

        if let Some(chain_id) = meta.chain_id {
            payload.extend_from_slice(&chain_id.to_be_bytes());
        }

        // Check to see if this data needs to be split up and
        // sent in chunks.
        let max_size = MAX_CHUNK_SIZE - payload.len();
        let empty = vec![];
        let (data, remaining_data) = if data.len() > max_size {
            data.split_at(max_size)
        } else {
            (data, empty.as_ref())
        };

        // Pack the first chunk
        payload.extend_from_slice(data);
        trace!("Serialized payload length {:?}", payload.len());

        let p2 = if remaining_data.is_empty() {
            0
        } else {
            P2_MORE
        };

        let p1 = P1_CONFIRM;
        let mut result = self.send_apdu(commands::SIGN_TRANSACTION, p1, p2, &payload)?;

        // Pack and send the remaining chunks
        if !remaining_data.is_empty() {
            let mut chunks: Vec<_> = remaining_data
                .chunks(MAX_CHUNK_SIZE)
                .map(|data| {
                    let payload = data.to_vec();
                    let p2 = P2_EXTEND | P2_MORE;
                    (p2, payload)
                })
                .collect();

            // Clear the P2_MORE bit on the last item.
            chunks.last_mut().unwrap().0 &= !P2_MORE;

            for (p2, payload) in chunks {
                result = self.send_apdu(commands::SIGN_TRANSACTION, p1, p2, &payload)?;
            }
        }

        if result.len() != SIGNATURE_LENGTH + 1 {
            return Err(RemoteWalletError::Protocol(
                "Signature packet size mismatch",
            ));
        }
        Ok(Signature::from_bytes(&result[1..])?)
    }
}

#[derive(Clone, Copy, Default)]
pub struct SignTransactionMeta {
    chain_id: Option<u32>,
    workchain_id: Option<u8>,
    current_wallet_type: Option<WalletType>,
}

impl SignTransactionMeta {
    pub fn new(
        chain_id: Option<u32>,
        workchain_id: Option<u8>,
        current_wallet_type: Option<WalletType>,
    ) -> Self {
        Self {
            chain_id,
            workchain_id,
            current_wallet_type,
        }
    }
}

/// Check if the detected device is a valid `Ledger device` by checking both the product ID and the vendor ID
pub fn is_valid_ledger(vendor_id: u16, product_id: u16) -> bool {
    let product_ids = [
        LEDGER_NANO_S_PIDS,
        LEDGER_NANO_X_PIDS,
        LEDGER_NANO_S_PLUS_PIDS,
        LEDGER_STAX_PIDS,
        LEDGER_FLEX_PIDS,
    ];
    vendor_id == LEDGER_VID && product_ids.iter().any(|pids| pids.contains(&product_id))
}

/// Choose a Ledger wallet based on matching info fields
pub fn get_ledger_from_info(
    info: RemoteWalletInfo,
    keypair_name: &str,
    wallet_manager: &RemoteWalletManager,
) -> Result<Rc<LedgerWallet>, RemoteWalletError> {
    let devices = wallet_manager.list_devices();
    let mut matches = devices
        .iter()
        .filter(|&device_info| device_info.matches(&info));
    if matches
        .clone()
        .all(|device_info| device_info.error.is_some())
    {
        let first_device = matches.next();
        if let Some(device) = first_device {
            return Err(device.error.clone().unwrap());
        }
    }
    let mut matches: Vec<(String, String)> = matches
        .filter(|&device_info| device_info.error.is_none())
        .map(|device_info| {
            let query_item = format!("{} ({})", device_info.get_pretty_path(), device_info.model,);
            (device_info.host_device_path.clone(), query_item)
        })
        .collect();
    if matches.is_empty() {
        return Err(RemoteWalletError::NoDeviceFound);
    }
    matches.sort_by(|a, b| a.1.cmp(&b.1));
    let (host_device_paths, items): (Vec<String>, Vec<String>) = matches.into_iter().unzip();

    let wallet_host_device_path = if host_device_paths.len() > 1 {
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt(format!(
                "Multiple hardware wallets found. Please select a device for {keypair_name:?}"
            ))
            .default(0)
            .items(&items[..])
            .interact()
            .unwrap();
        &host_device_paths[selection]
    } else {
        &host_device_paths[0]
    };
    wallet_manager.get_ledger(wallet_host_device_path)
}

//
fn is_last_part(p2: u8) -> bool {
    p2 & P2_MORE == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_last_part() {
        // Bytes with bit-2 set to 0 should return true
        assert!(is_last_part(0b00));
        assert!(is_last_part(0b01));
        assert!(is_last_part(0b101));
        assert!(is_last_part(0b1001));
        assert!(is_last_part(0b1101));

        // Bytes with bit-2 set to 1 should return false
        assert!(!is_last_part(0b10));
        assert!(!is_last_part(0b11));
        assert!(!is_last_part(0b110));
        assert!(!is_last_part(0b111));
        assert!(!is_last_part(0b1010));

        // Test implementation-specific uses
        let p2 = 0;
        assert!(is_last_part(p2));
        let p2 = P2_EXTEND | P2_MORE;
        assert!(!is_last_part(p2));
        assert!(is_last_part(p2 & !P2_MORE));
    }

    #[test]
    fn test_parse_status() {
        LedgerWallet::parse_status(APDU_SUCCESS_CODE).expect("unexpected result");
        if let RemoteWalletError::LedgerError(err) = LedgerWallet::parse_status(0x6985).unwrap_err()
        {
            assert_eq!(err, LedgerError::UserCancel);
        }
        if let RemoteWalletError::Protocol(err) = LedgerWallet::parse_status(0x6fff).unwrap_err() {
            assert_eq!(err, "Unknown error");
        }
    }
}
