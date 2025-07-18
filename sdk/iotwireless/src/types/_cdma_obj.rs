// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>CDMA (Code-division multiple access) object.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CdmaObj {
    /// <p>CDMA system ID (SID).</p>
    pub system_id: i32,
    /// <p>CDMA network ID (NID).</p>
    pub network_id: i32,
    /// <p>CDMA base station ID (BSID).</p>
    pub base_station_id: i32,
    /// <p>CDMA registration zone (RZ).</p>
    pub registration_zone: ::std::option::Option<i32>,
    /// <p>CDMA local identification (local ID) parameters.</p>
    pub cdma_local_id: ::std::option::Option<crate::types::CdmaLocalId>,
    /// <p>Transmit power level of the pilot signal, measured in dBm (decibel-milliwatts).</p>
    pub pilot_power: ::std::option::Option<i32>,
    /// <p>CDMA base station latitude in degrees.</p>
    pub base_lat: ::std::option::Option<f32>,
    /// <p>CDMA base station longitude in degrees.</p>
    pub base_lng: ::std::option::Option<f32>,
    /// <p>CDMA network measurement reports.</p>
    pub cdma_nmr: ::std::option::Option<::std::vec::Vec<crate::types::CdmaNmrObj>>,
}
impl CdmaObj {
    /// <p>CDMA system ID (SID).</p>
    pub fn system_id(&self) -> i32 {
        self.system_id
    }
    /// <p>CDMA network ID (NID).</p>
    pub fn network_id(&self) -> i32 {
        self.network_id
    }
    /// <p>CDMA base station ID (BSID).</p>
    pub fn base_station_id(&self) -> i32 {
        self.base_station_id
    }
    /// <p>CDMA registration zone (RZ).</p>
    pub fn registration_zone(&self) -> ::std::option::Option<i32> {
        self.registration_zone
    }
    /// <p>CDMA local identification (local ID) parameters.</p>
    pub fn cdma_local_id(&self) -> ::std::option::Option<&crate::types::CdmaLocalId> {
        self.cdma_local_id.as_ref()
    }
    /// <p>Transmit power level of the pilot signal, measured in dBm (decibel-milliwatts).</p>
    pub fn pilot_power(&self) -> ::std::option::Option<i32> {
        self.pilot_power
    }
    /// <p>CDMA base station latitude in degrees.</p>
    pub fn base_lat(&self) -> ::std::option::Option<f32> {
        self.base_lat
    }
    /// <p>CDMA base station longitude in degrees.</p>
    pub fn base_lng(&self) -> ::std::option::Option<f32> {
        self.base_lng
    }
    /// <p>CDMA network measurement reports.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.cdma_nmr.is_none()`.
    pub fn cdma_nmr(&self) -> &[crate::types::CdmaNmrObj] {
        self.cdma_nmr.as_deref().unwrap_or_default()
    }
}
impl CdmaObj {
    /// Creates a new builder-style object to manufacture [`CdmaObj`](crate::types::CdmaObj).
    pub fn builder() -> crate::types::builders::CdmaObjBuilder {
        crate::types::builders::CdmaObjBuilder::default()
    }
}

/// A builder for [`CdmaObj`](crate::types::CdmaObj).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CdmaObjBuilder {
    pub(crate) system_id: ::std::option::Option<i32>,
    pub(crate) network_id: ::std::option::Option<i32>,
    pub(crate) base_station_id: ::std::option::Option<i32>,
    pub(crate) registration_zone: ::std::option::Option<i32>,
    pub(crate) cdma_local_id: ::std::option::Option<crate::types::CdmaLocalId>,
    pub(crate) pilot_power: ::std::option::Option<i32>,
    pub(crate) base_lat: ::std::option::Option<f32>,
    pub(crate) base_lng: ::std::option::Option<f32>,
    pub(crate) cdma_nmr: ::std::option::Option<::std::vec::Vec<crate::types::CdmaNmrObj>>,
}
impl CdmaObjBuilder {
    /// <p>CDMA system ID (SID).</p>
    /// This field is required.
    pub fn system_id(mut self, input: i32) -> Self {
        self.system_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>CDMA system ID (SID).</p>
    pub fn set_system_id(mut self, input: ::std::option::Option<i32>) -> Self {
        self.system_id = input;
        self
    }
    /// <p>CDMA system ID (SID).</p>
    pub fn get_system_id(&self) -> &::std::option::Option<i32> {
        &self.system_id
    }
    /// <p>CDMA network ID (NID).</p>
    /// This field is required.
    pub fn network_id(mut self, input: i32) -> Self {
        self.network_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>CDMA network ID (NID).</p>
    pub fn set_network_id(mut self, input: ::std::option::Option<i32>) -> Self {
        self.network_id = input;
        self
    }
    /// <p>CDMA network ID (NID).</p>
    pub fn get_network_id(&self) -> &::std::option::Option<i32> {
        &self.network_id
    }
    /// <p>CDMA base station ID (BSID).</p>
    /// This field is required.
    pub fn base_station_id(mut self, input: i32) -> Self {
        self.base_station_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>CDMA base station ID (BSID).</p>
    pub fn set_base_station_id(mut self, input: ::std::option::Option<i32>) -> Self {
        self.base_station_id = input;
        self
    }
    /// <p>CDMA base station ID (BSID).</p>
    pub fn get_base_station_id(&self) -> &::std::option::Option<i32> {
        &self.base_station_id
    }
    /// <p>CDMA registration zone (RZ).</p>
    pub fn registration_zone(mut self, input: i32) -> Self {
        self.registration_zone = ::std::option::Option::Some(input);
        self
    }
    /// <p>CDMA registration zone (RZ).</p>
    pub fn set_registration_zone(mut self, input: ::std::option::Option<i32>) -> Self {
        self.registration_zone = input;
        self
    }
    /// <p>CDMA registration zone (RZ).</p>
    pub fn get_registration_zone(&self) -> &::std::option::Option<i32> {
        &self.registration_zone
    }
    /// <p>CDMA local identification (local ID) parameters.</p>
    pub fn cdma_local_id(mut self, input: crate::types::CdmaLocalId) -> Self {
        self.cdma_local_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>CDMA local identification (local ID) parameters.</p>
    pub fn set_cdma_local_id(mut self, input: ::std::option::Option<crate::types::CdmaLocalId>) -> Self {
        self.cdma_local_id = input;
        self
    }
    /// <p>CDMA local identification (local ID) parameters.</p>
    pub fn get_cdma_local_id(&self) -> &::std::option::Option<crate::types::CdmaLocalId> {
        &self.cdma_local_id
    }
    /// <p>Transmit power level of the pilot signal, measured in dBm (decibel-milliwatts).</p>
    pub fn pilot_power(mut self, input: i32) -> Self {
        self.pilot_power = ::std::option::Option::Some(input);
        self
    }
    /// <p>Transmit power level of the pilot signal, measured in dBm (decibel-milliwatts).</p>
    pub fn set_pilot_power(mut self, input: ::std::option::Option<i32>) -> Self {
        self.pilot_power = input;
        self
    }
    /// <p>Transmit power level of the pilot signal, measured in dBm (decibel-milliwatts).</p>
    pub fn get_pilot_power(&self) -> &::std::option::Option<i32> {
        &self.pilot_power
    }
    /// <p>CDMA base station latitude in degrees.</p>
    pub fn base_lat(mut self, input: f32) -> Self {
        self.base_lat = ::std::option::Option::Some(input);
        self
    }
    /// <p>CDMA base station latitude in degrees.</p>
    pub fn set_base_lat(mut self, input: ::std::option::Option<f32>) -> Self {
        self.base_lat = input;
        self
    }
    /// <p>CDMA base station latitude in degrees.</p>
    pub fn get_base_lat(&self) -> &::std::option::Option<f32> {
        &self.base_lat
    }
    /// <p>CDMA base station longitude in degrees.</p>
    pub fn base_lng(mut self, input: f32) -> Self {
        self.base_lng = ::std::option::Option::Some(input);
        self
    }
    /// <p>CDMA base station longitude in degrees.</p>
    pub fn set_base_lng(mut self, input: ::std::option::Option<f32>) -> Self {
        self.base_lng = input;
        self
    }
    /// <p>CDMA base station longitude in degrees.</p>
    pub fn get_base_lng(&self) -> &::std::option::Option<f32> {
        &self.base_lng
    }
    /// Appends an item to `cdma_nmr`.
    ///
    /// To override the contents of this collection use [`set_cdma_nmr`](Self::set_cdma_nmr).
    ///
    /// <p>CDMA network measurement reports.</p>
    pub fn cdma_nmr(mut self, input: crate::types::CdmaNmrObj) -> Self {
        let mut v = self.cdma_nmr.unwrap_or_default();
        v.push(input);
        self.cdma_nmr = ::std::option::Option::Some(v);
        self
    }
    /// <p>CDMA network measurement reports.</p>
    pub fn set_cdma_nmr(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CdmaNmrObj>>) -> Self {
        self.cdma_nmr = input;
        self
    }
    /// <p>CDMA network measurement reports.</p>
    pub fn get_cdma_nmr(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CdmaNmrObj>> {
        &self.cdma_nmr
    }
    /// Consumes the builder and constructs a [`CdmaObj`](crate::types::CdmaObj).
    /// This method will fail if any of the following fields are not set:
    /// - [`system_id`](crate::types::builders::CdmaObjBuilder::system_id)
    /// - [`network_id`](crate::types::builders::CdmaObjBuilder::network_id)
    /// - [`base_station_id`](crate::types::builders::CdmaObjBuilder::base_station_id)
    pub fn build(self) -> ::std::result::Result<crate::types::CdmaObj, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CdmaObj {
            system_id: self.system_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "system_id",
                    "system_id was not specified but it is required when building CdmaObj",
                )
            })?,
            network_id: self.network_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "network_id",
                    "network_id was not specified but it is required when building CdmaObj",
                )
            })?,
            base_station_id: self.base_station_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "base_station_id",
                    "base_station_id was not specified but it is required when building CdmaObj",
                )
            })?,
            registration_zone: self.registration_zone,
            cdma_local_id: self.cdma_local_id,
            pilot_power: self.pilot_power,
            base_lat: self.base_lat,
            base_lng: self.base_lng,
            cdma_nmr: self.cdma_nmr,
        })
    }
}
