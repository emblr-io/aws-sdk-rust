// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information for an asset property historical value entry that is associated with the <a href="https://docs.aws.amazon.com/iot-sitewise/latest/APIReference/API_BatchGetAssetPropertyValue.html">BatchGetAssetPropertyValueHistory</a> API.</p>
/// <p>To identify an asset property, you must specify one of the following:</p>
/// <ul>
/// <li>
/// <p>The <code>assetId</code> and <code>propertyId</code> of an asset property.</p></li>
/// <li>
/// <p>A <code>propertyAlias</code>, which is a data stream alias (for example, <code>/company/windfarm/3/turbine/7/temperature</code>). To define an asset property's alias, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/APIReference/API_UpdateAssetProperty.html">UpdateAssetProperty</a>.</p></li>
/// </ul>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchGetAssetPropertyValueHistoryEntry {
    /// <p>The ID of the entry.</p>
    pub entry_id: ::std::string::String,
    /// <p>The ID of the asset in which the asset property was created.</p>
    pub asset_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the asset property, in UUID format.</p>
    pub property_id: ::std::option::Option<::std::string::String>,
    /// <p>The alias that identifies the property, such as an OPC-UA server data stream path (for example, <code>/company/windfarm/3/turbine/7/temperature</code>). For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/connect-data-streams.html">Mapping industrial data streams to asset properties</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub property_alias: ::std::option::Option<::std::string::String>,
    /// <p>The exclusive start of the range from which to query historical data, expressed in seconds in Unix epoch time.</p>
    pub start_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The inclusive end of the range from which to query historical data, expressed in seconds in Unix epoch time.</p>
    pub end_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The quality by which to filter asset data.</p>
    pub qualities: ::std::option::Option<::std::vec::Vec<crate::types::Quality>>,
    /// <p>The chronological sorting order of the requested information.</p>
    /// <p>Default: <code>ASCENDING</code></p>
    pub time_ordering: ::std::option::Option<crate::types::TimeOrdering>,
}
impl BatchGetAssetPropertyValueHistoryEntry {
    /// <p>The ID of the entry.</p>
    pub fn entry_id(&self) -> &str {
        use std::ops::Deref;
        self.entry_id.deref()
    }
    /// <p>The ID of the asset in which the asset property was created.</p>
    pub fn asset_id(&self) -> ::std::option::Option<&str> {
        self.asset_id.as_deref()
    }
    /// <p>The ID of the asset property, in UUID format.</p>
    pub fn property_id(&self) -> ::std::option::Option<&str> {
        self.property_id.as_deref()
    }
    /// <p>The alias that identifies the property, such as an OPC-UA server data stream path (for example, <code>/company/windfarm/3/turbine/7/temperature</code>). For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/connect-data-streams.html">Mapping industrial data streams to asset properties</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn property_alias(&self) -> ::std::option::Option<&str> {
        self.property_alias.as_deref()
    }
    /// <p>The exclusive start of the range from which to query historical data, expressed in seconds in Unix epoch time.</p>
    pub fn start_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_date.as_ref()
    }
    /// <p>The inclusive end of the range from which to query historical data, expressed in seconds in Unix epoch time.</p>
    pub fn end_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_date.as_ref()
    }
    /// <p>The quality by which to filter asset data.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.qualities.is_none()`.
    pub fn qualities(&self) -> &[crate::types::Quality] {
        self.qualities.as_deref().unwrap_or_default()
    }
    /// <p>The chronological sorting order of the requested information.</p>
    /// <p>Default: <code>ASCENDING</code></p>
    pub fn time_ordering(&self) -> ::std::option::Option<&crate::types::TimeOrdering> {
        self.time_ordering.as_ref()
    }
}
impl BatchGetAssetPropertyValueHistoryEntry {
    /// Creates a new builder-style object to manufacture [`BatchGetAssetPropertyValueHistoryEntry`](crate::types::BatchGetAssetPropertyValueHistoryEntry).
    pub fn builder() -> crate::types::builders::BatchGetAssetPropertyValueHistoryEntryBuilder {
        crate::types::builders::BatchGetAssetPropertyValueHistoryEntryBuilder::default()
    }
}

/// A builder for [`BatchGetAssetPropertyValueHistoryEntry`](crate::types::BatchGetAssetPropertyValueHistoryEntry).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchGetAssetPropertyValueHistoryEntryBuilder {
    pub(crate) entry_id: ::std::option::Option<::std::string::String>,
    pub(crate) asset_id: ::std::option::Option<::std::string::String>,
    pub(crate) property_id: ::std::option::Option<::std::string::String>,
    pub(crate) property_alias: ::std::option::Option<::std::string::String>,
    pub(crate) start_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) qualities: ::std::option::Option<::std::vec::Vec<crate::types::Quality>>,
    pub(crate) time_ordering: ::std::option::Option<crate::types::TimeOrdering>,
}
impl BatchGetAssetPropertyValueHistoryEntryBuilder {
    /// <p>The ID of the entry.</p>
    /// This field is required.
    pub fn entry_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.entry_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the entry.</p>
    pub fn set_entry_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.entry_id = input;
        self
    }
    /// <p>The ID of the entry.</p>
    pub fn get_entry_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.entry_id
    }
    /// <p>The ID of the asset in which the asset property was created.</p>
    pub fn asset_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.asset_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the asset in which the asset property was created.</p>
    pub fn set_asset_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.asset_id = input;
        self
    }
    /// <p>The ID of the asset in which the asset property was created.</p>
    pub fn get_asset_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.asset_id
    }
    /// <p>The ID of the asset property, in UUID format.</p>
    pub fn property_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.property_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the asset property, in UUID format.</p>
    pub fn set_property_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.property_id = input;
        self
    }
    /// <p>The ID of the asset property, in UUID format.</p>
    pub fn get_property_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.property_id
    }
    /// <p>The alias that identifies the property, such as an OPC-UA server data stream path (for example, <code>/company/windfarm/3/turbine/7/temperature</code>). For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/connect-data-streams.html">Mapping industrial data streams to asset properties</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn property_alias(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.property_alias = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The alias that identifies the property, such as an OPC-UA server data stream path (for example, <code>/company/windfarm/3/turbine/7/temperature</code>). For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/connect-data-streams.html">Mapping industrial data streams to asset properties</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn set_property_alias(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.property_alias = input;
        self
    }
    /// <p>The alias that identifies the property, such as an OPC-UA server data stream path (for example, <code>/company/windfarm/3/turbine/7/temperature</code>). For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/connect-data-streams.html">Mapping industrial data streams to asset properties</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn get_property_alias(&self) -> &::std::option::Option<::std::string::String> {
        &self.property_alias
    }
    /// <p>The exclusive start of the range from which to query historical data, expressed in seconds in Unix epoch time.</p>
    pub fn start_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The exclusive start of the range from which to query historical data, expressed in seconds in Unix epoch time.</p>
    pub fn set_start_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_date = input;
        self
    }
    /// <p>The exclusive start of the range from which to query historical data, expressed in seconds in Unix epoch time.</p>
    pub fn get_start_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_date
    }
    /// <p>The inclusive end of the range from which to query historical data, expressed in seconds in Unix epoch time.</p>
    pub fn end_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The inclusive end of the range from which to query historical data, expressed in seconds in Unix epoch time.</p>
    pub fn set_end_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_date = input;
        self
    }
    /// <p>The inclusive end of the range from which to query historical data, expressed in seconds in Unix epoch time.</p>
    pub fn get_end_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_date
    }
    /// Appends an item to `qualities`.
    ///
    /// To override the contents of this collection use [`set_qualities`](Self::set_qualities).
    ///
    /// <p>The quality by which to filter asset data.</p>
    pub fn qualities(mut self, input: crate::types::Quality) -> Self {
        let mut v = self.qualities.unwrap_or_default();
        v.push(input);
        self.qualities = ::std::option::Option::Some(v);
        self
    }
    /// <p>The quality by which to filter asset data.</p>
    pub fn set_qualities(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Quality>>) -> Self {
        self.qualities = input;
        self
    }
    /// <p>The quality by which to filter asset data.</p>
    pub fn get_qualities(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Quality>> {
        &self.qualities
    }
    /// <p>The chronological sorting order of the requested information.</p>
    /// <p>Default: <code>ASCENDING</code></p>
    pub fn time_ordering(mut self, input: crate::types::TimeOrdering) -> Self {
        self.time_ordering = ::std::option::Option::Some(input);
        self
    }
    /// <p>The chronological sorting order of the requested information.</p>
    /// <p>Default: <code>ASCENDING</code></p>
    pub fn set_time_ordering(mut self, input: ::std::option::Option<crate::types::TimeOrdering>) -> Self {
        self.time_ordering = input;
        self
    }
    /// <p>The chronological sorting order of the requested information.</p>
    /// <p>Default: <code>ASCENDING</code></p>
    pub fn get_time_ordering(&self) -> &::std::option::Option<crate::types::TimeOrdering> {
        &self.time_ordering
    }
    /// Consumes the builder and constructs a [`BatchGetAssetPropertyValueHistoryEntry`](crate::types::BatchGetAssetPropertyValueHistoryEntry).
    /// This method will fail if any of the following fields are not set:
    /// - [`entry_id`](crate::types::builders::BatchGetAssetPropertyValueHistoryEntryBuilder::entry_id)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::BatchGetAssetPropertyValueHistoryEntry, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::BatchGetAssetPropertyValueHistoryEntry {
            entry_id: self.entry_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "entry_id",
                    "entry_id was not specified but it is required when building BatchGetAssetPropertyValueHistoryEntry",
                )
            })?,
            asset_id: self.asset_id,
            property_id: self.property_id,
            property_alias: self.property_alias,
            start_date: self.start_date,
            end_date: self.end_date,
            qualities: self.qualities,
            time_ordering: self.time_ordering,
        })
    }
}
