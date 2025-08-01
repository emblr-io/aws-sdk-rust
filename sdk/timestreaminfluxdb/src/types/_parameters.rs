// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The parameters that comprise the parameter group.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum Parameters {
    /// <p>All the customer-modifiable InfluxDB v2 parameters in Timestream for InfluxDB.</p>
    InfluxDBv2(crate::types::InfluxDBv2Parameters),
    /// The `Unknown` variant represents cases where new union variant was received. Consider upgrading the SDK to the latest available version.
    /// An unknown enum variant
    ///
    /// _Note: If you encounter this error, consider upgrading your SDK to the latest version._
    /// The `Unknown` variant represents cases where the server sent a value that wasn't recognized
    /// by the client. This can happen when the server adds new functionality, but the client has not been updated.
    /// To investigate this, consider turning on debug logging to print the raw HTTP response.
    #[non_exhaustive]
    Unknown,
}
impl Parameters {
    #[allow(irrefutable_let_patterns)]
    /// Tries to convert the enum instance into [`InfluxDBv2`](crate::types::Parameters::InfluxDBv2), extracting the inner [`InfluxDBv2Parameters`](crate::types::InfluxDBv2Parameters).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_influx_dbv2(&self) -> ::std::result::Result<&crate::types::InfluxDBv2Parameters, &Self> {
        if let Parameters::InfluxDBv2(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`InfluxDBv2`](crate::types::Parameters::InfluxDBv2).
    pub fn is_influx_dbv2(&self) -> bool {
        self.as_influx_dbv2().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
