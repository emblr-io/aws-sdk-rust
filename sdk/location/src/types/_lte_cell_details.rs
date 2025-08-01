// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about the Long-Term Evolution (LTE) network.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LteCellDetails {
    /// <p>The E-UTRAN Cell Identifier (ECI).</p>
    pub cell_id: i32,
    /// <p>The Mobile Country Code (MCC).</p>
    pub mcc: i32,
    /// <p>The Mobile Network Code (MNC)</p>
    pub mnc: i32,
    /// <p>The LTE local identification information (local ID).</p>
    pub local_id: ::std::option::Option<crate::types::LteLocalId>,
    /// <p>The network measurements.</p>
    pub network_measurements: ::std::option::Option<::std::vec::Vec<crate::types::LteNetworkMeasurements>>,
    /// <p>Timing Advance (TA).</p>
    pub timing_advance: ::std::option::Option<i32>,
    /// <p>Indicates whether the LTE object is capable of supporting NR (new radio).</p>
    pub nr_capable: ::std::option::Option<bool>,
    /// <p>Signal power of the reference signal received, measured in decibel-milliwatts (dBm).</p>
    pub rsrp: ::std::option::Option<i32>,
    /// <p>Signal quality of the reference Signal received, measured in decibels (dB).</p>
    pub rsrq: ::std::option::Option<f32>,
    /// <p>LTE Tracking Area Code (TAC).</p>
    pub tac: ::std::option::Option<i32>,
}
impl LteCellDetails {
    /// <p>The E-UTRAN Cell Identifier (ECI).</p>
    pub fn cell_id(&self) -> i32 {
        self.cell_id
    }
    /// <p>The Mobile Country Code (MCC).</p>
    pub fn mcc(&self) -> i32 {
        self.mcc
    }
    /// <p>The Mobile Network Code (MNC)</p>
    pub fn mnc(&self) -> i32 {
        self.mnc
    }
    /// <p>The LTE local identification information (local ID).</p>
    pub fn local_id(&self) -> ::std::option::Option<&crate::types::LteLocalId> {
        self.local_id.as_ref()
    }
    /// <p>The network measurements.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.network_measurements.is_none()`.
    pub fn network_measurements(&self) -> &[crate::types::LteNetworkMeasurements] {
        self.network_measurements.as_deref().unwrap_or_default()
    }
    /// <p>Timing Advance (TA).</p>
    pub fn timing_advance(&self) -> ::std::option::Option<i32> {
        self.timing_advance
    }
    /// <p>Indicates whether the LTE object is capable of supporting NR (new radio).</p>
    pub fn nr_capable(&self) -> ::std::option::Option<bool> {
        self.nr_capable
    }
    /// <p>Signal power of the reference signal received, measured in decibel-milliwatts (dBm).</p>
    pub fn rsrp(&self) -> ::std::option::Option<i32> {
        self.rsrp
    }
    /// <p>Signal quality of the reference Signal received, measured in decibels (dB).</p>
    pub fn rsrq(&self) -> ::std::option::Option<f32> {
        self.rsrq
    }
    /// <p>LTE Tracking Area Code (TAC).</p>
    pub fn tac(&self) -> ::std::option::Option<i32> {
        self.tac
    }
}
impl LteCellDetails {
    /// Creates a new builder-style object to manufacture [`LteCellDetails`](crate::types::LteCellDetails).
    pub fn builder() -> crate::types::builders::LteCellDetailsBuilder {
        crate::types::builders::LteCellDetailsBuilder::default()
    }
}

/// A builder for [`LteCellDetails`](crate::types::LteCellDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LteCellDetailsBuilder {
    pub(crate) cell_id: ::std::option::Option<i32>,
    pub(crate) mcc: ::std::option::Option<i32>,
    pub(crate) mnc: ::std::option::Option<i32>,
    pub(crate) local_id: ::std::option::Option<crate::types::LteLocalId>,
    pub(crate) network_measurements: ::std::option::Option<::std::vec::Vec<crate::types::LteNetworkMeasurements>>,
    pub(crate) timing_advance: ::std::option::Option<i32>,
    pub(crate) nr_capable: ::std::option::Option<bool>,
    pub(crate) rsrp: ::std::option::Option<i32>,
    pub(crate) rsrq: ::std::option::Option<f32>,
    pub(crate) tac: ::std::option::Option<i32>,
}
impl LteCellDetailsBuilder {
    /// <p>The E-UTRAN Cell Identifier (ECI).</p>
    /// This field is required.
    pub fn cell_id(mut self, input: i32) -> Self {
        self.cell_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>The E-UTRAN Cell Identifier (ECI).</p>
    pub fn set_cell_id(mut self, input: ::std::option::Option<i32>) -> Self {
        self.cell_id = input;
        self
    }
    /// <p>The E-UTRAN Cell Identifier (ECI).</p>
    pub fn get_cell_id(&self) -> &::std::option::Option<i32> {
        &self.cell_id
    }
    /// <p>The Mobile Country Code (MCC).</p>
    /// This field is required.
    pub fn mcc(mut self, input: i32) -> Self {
        self.mcc = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Mobile Country Code (MCC).</p>
    pub fn set_mcc(mut self, input: ::std::option::Option<i32>) -> Self {
        self.mcc = input;
        self
    }
    /// <p>The Mobile Country Code (MCC).</p>
    pub fn get_mcc(&self) -> &::std::option::Option<i32> {
        &self.mcc
    }
    /// <p>The Mobile Network Code (MNC)</p>
    /// This field is required.
    pub fn mnc(mut self, input: i32) -> Self {
        self.mnc = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Mobile Network Code (MNC)</p>
    pub fn set_mnc(mut self, input: ::std::option::Option<i32>) -> Self {
        self.mnc = input;
        self
    }
    /// <p>The Mobile Network Code (MNC)</p>
    pub fn get_mnc(&self) -> &::std::option::Option<i32> {
        &self.mnc
    }
    /// <p>The LTE local identification information (local ID).</p>
    pub fn local_id(mut self, input: crate::types::LteLocalId) -> Self {
        self.local_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>The LTE local identification information (local ID).</p>
    pub fn set_local_id(mut self, input: ::std::option::Option<crate::types::LteLocalId>) -> Self {
        self.local_id = input;
        self
    }
    /// <p>The LTE local identification information (local ID).</p>
    pub fn get_local_id(&self) -> &::std::option::Option<crate::types::LteLocalId> {
        &self.local_id
    }
    /// Appends an item to `network_measurements`.
    ///
    /// To override the contents of this collection use [`set_network_measurements`](Self::set_network_measurements).
    ///
    /// <p>The network measurements.</p>
    pub fn network_measurements(mut self, input: crate::types::LteNetworkMeasurements) -> Self {
        let mut v = self.network_measurements.unwrap_or_default();
        v.push(input);
        self.network_measurements = ::std::option::Option::Some(v);
        self
    }
    /// <p>The network measurements.</p>
    pub fn set_network_measurements(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::LteNetworkMeasurements>>) -> Self {
        self.network_measurements = input;
        self
    }
    /// <p>The network measurements.</p>
    pub fn get_network_measurements(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LteNetworkMeasurements>> {
        &self.network_measurements
    }
    /// <p>Timing Advance (TA).</p>
    pub fn timing_advance(mut self, input: i32) -> Self {
        self.timing_advance = ::std::option::Option::Some(input);
        self
    }
    /// <p>Timing Advance (TA).</p>
    pub fn set_timing_advance(mut self, input: ::std::option::Option<i32>) -> Self {
        self.timing_advance = input;
        self
    }
    /// <p>Timing Advance (TA).</p>
    pub fn get_timing_advance(&self) -> &::std::option::Option<i32> {
        &self.timing_advance
    }
    /// <p>Indicates whether the LTE object is capable of supporting NR (new radio).</p>
    pub fn nr_capable(mut self, input: bool) -> Self {
        self.nr_capable = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the LTE object is capable of supporting NR (new radio).</p>
    pub fn set_nr_capable(mut self, input: ::std::option::Option<bool>) -> Self {
        self.nr_capable = input;
        self
    }
    /// <p>Indicates whether the LTE object is capable of supporting NR (new radio).</p>
    pub fn get_nr_capable(&self) -> &::std::option::Option<bool> {
        &self.nr_capable
    }
    /// <p>Signal power of the reference signal received, measured in decibel-milliwatts (dBm).</p>
    pub fn rsrp(mut self, input: i32) -> Self {
        self.rsrp = ::std::option::Option::Some(input);
        self
    }
    /// <p>Signal power of the reference signal received, measured in decibel-milliwatts (dBm).</p>
    pub fn set_rsrp(mut self, input: ::std::option::Option<i32>) -> Self {
        self.rsrp = input;
        self
    }
    /// <p>Signal power of the reference signal received, measured in decibel-milliwatts (dBm).</p>
    pub fn get_rsrp(&self) -> &::std::option::Option<i32> {
        &self.rsrp
    }
    /// <p>Signal quality of the reference Signal received, measured in decibels (dB).</p>
    pub fn rsrq(mut self, input: f32) -> Self {
        self.rsrq = ::std::option::Option::Some(input);
        self
    }
    /// <p>Signal quality of the reference Signal received, measured in decibels (dB).</p>
    pub fn set_rsrq(mut self, input: ::std::option::Option<f32>) -> Self {
        self.rsrq = input;
        self
    }
    /// <p>Signal quality of the reference Signal received, measured in decibels (dB).</p>
    pub fn get_rsrq(&self) -> &::std::option::Option<f32> {
        &self.rsrq
    }
    /// <p>LTE Tracking Area Code (TAC).</p>
    pub fn tac(mut self, input: i32) -> Self {
        self.tac = ::std::option::Option::Some(input);
        self
    }
    /// <p>LTE Tracking Area Code (TAC).</p>
    pub fn set_tac(mut self, input: ::std::option::Option<i32>) -> Self {
        self.tac = input;
        self
    }
    /// <p>LTE Tracking Area Code (TAC).</p>
    pub fn get_tac(&self) -> &::std::option::Option<i32> {
        &self.tac
    }
    /// Consumes the builder and constructs a [`LteCellDetails`](crate::types::LteCellDetails).
    /// This method will fail if any of the following fields are not set:
    /// - [`mcc`](crate::types::builders::LteCellDetailsBuilder::mcc)
    /// - [`mnc`](crate::types::builders::LteCellDetailsBuilder::mnc)
    pub fn build(self) -> ::std::result::Result<crate::types::LteCellDetails, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::LteCellDetails {
            cell_id: self.cell_id.unwrap_or_default(),
            mcc: self.mcc.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "mcc",
                    "mcc was not specified but it is required when building LteCellDetails",
                )
            })?,
            mnc: self.mnc.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "mnc",
                    "mnc was not specified but it is required when building LteCellDetails",
                )
            })?,
            local_id: self.local_id,
            network_measurements: self.network_measurements,
            timing_advance: self.timing_advance,
            nr_capable: self.nr_capable,
            rsrp: self.rsrp,
            rsrq: self.rsrq,
            tac: self.tac,
        })
    }
}
