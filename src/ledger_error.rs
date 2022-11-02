use {num_derive::FromPrimitive, thiserror::Error};

#[derive(Error, Debug, Clone, FromPrimitive, PartialEq, Eq)]
pub enum LedgerError {
    #[error("Everscale app not open on Ledger device")]
    NoAppResponse = 0x6700,

    #[error("Ledger sdk exception")]
    SdkException = 0x6801,

    #[error("Ledger invalid parameter")]
    SdkInvalidParameter = 0x6802,

    #[error("Ledger overflow")]
    SdkExceptionOverflow = 0x6803,

    #[error("Ledger security exception")]
    SdkExceptionSecurity = 0x6804,

    #[error("Ledger invalid CRC")]
    SdkInvalidCrc = 0x6805,

    #[error("Ledger invalid checksum")]
    SdkInvalidChecksum = 0x6806,

    #[error("Ledger invalid counter")]
    SdkInvalidCounter = 0x6807,

    #[error("Ledger operation not supported")]
    SdkNotSupported = 0x6808,

    #[error("Ledger invalid state")]
    SdkInvalidState = 0x6809,

    #[error("Ledger timeout")]
    SdkTimeout = 0x6810,

    #[error("Ledger PIC exception")]
    SdkExceptionPic = 0x6811,

    #[error("Ledger app exit exception")]
    SdkExceptionAppExit = 0x6812,

    #[error("Ledger IO overflow exception")]
    SdkExceptionIoOverflow = 0x6813,

    #[error("Ledger IO header exception")]
    SdkExceptionIoHeader = 0x6814,

    #[error("Ledger IO state exception")]
    SdkExceptionIoState = 0x6815,

    #[error("Ledger IO reset exception")]
    SdkExceptionIoReset = 0x6816,

    #[error("Ledger CX port exception")]
    SdkExceptionCxPort = 0x6817,

    #[error("Ledger system exception")]
    SdkExceptionSystem = 0x6818,

    #[error("Ledger out of space")]
    SdkNotEnoughSpace = 0x6819,

    #[error("Ledger invalid counter")]
    NoApduReceived = 0x6982,

    #[error("Ledger operation rejected by the user")]
    UserCancel = 0x6985,

    #[error("Ledger received invalid Everscale message")]
    EverscaleInvalidData = 0x6b00,

    #[error("Everscale cell underflow error on Ledger")]
    EverscaleCellUnderflow = 0x6b01,

    #[error("Everscale invalid range error on Ledger")]
    EverscaleRangeCheck = 0x6b02,

    #[error("Everscale wrong label error on Ledger")]
    EverscaleWrongLabel = 0x6b03,

    #[error("Everscale invalid flag error on Ledger")]
    EverscaleInvalidFlag = 0x6b04,

    #[error("Everscale end of stream error on Ledger")]
    EverscaleEndOfStream = 0x6b05,

    #[error("Everscale empty slice error on Ledger")]
    EverscaleEmptySlice = 0x6b06,

    #[error("Everscale invalid key error on Ledger")]
    EverscaleInvalidKey = 0x6b07,

    #[error("Everscale empty cell error on Ledger")]
    EverscaleEmptyCell = 0x6b08,

    #[error("Everscale invalid hash error on Ledger")]
    EverscaleInvalidHash = 0x6b09,

    #[error("Everscale invalid cell index error on Ledger")]
    EverscaleInvalidCellIndex = 0x6b10,

    #[error("Everscale invalid request error on Ledger")]
    EverscaleInvalidRequest = 0x6b11,

    #[error("Everscale invalid function id error on Ledger")]
    EverscaleInvalidFunctionId = 0x6b12,

    #[error("Everscale invalid sender address error on Ledger")]
    EverscaleInvalidSrcAddress = 0x6b13,

    #[error("Everscale invalid wallet id error on Ledger")]
    EverscaleInvalidWalletId = 0x6b14,

    #[error("Everscale invalid wallet type error on Ledger")]
    EverscaleInvalidWalletType = 0x6b15,

    #[error("Ledger received unimplemented instruction")]
    UnimplementedInstruction = 0x6d00,

    #[error("Ledger received invalid CLA")]
    InvalidCla = 0x6e00,
}
