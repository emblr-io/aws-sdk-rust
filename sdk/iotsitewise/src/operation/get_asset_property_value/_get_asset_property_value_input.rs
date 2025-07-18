// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetAssetPropertyValueInput {
    /// <p>The ID of the asset, in UUID format.</p>
    pub asset_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the asset property, in UUID format.</p>
    pub property_id: ::std::option::Option<::std::string::String>,
    /// <p>The alias that identifies the property, such as an OPC-UA server data stream path (for example, <code>/company/windfarm/3/turbine/7/temperature</code>). For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/connect-data-streams.html">Mapping industrial data streams to asset properties</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub property_alias: ::std::option::Option<::std::string::String>,
}
impl GetAssetPropertyValueInput {
    /// <p>The ID of the asset, in UUID format.</p>
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
}
impl GetAssetPropertyValueInput {
    /// Creates a new builder-style object to manufacture [`GetAssetPropertyValueInput`](crate::operation::get_asset_property_value::GetAssetPropertyValueInput).
    pub fn builder() -> crate::operation::get_asset_property_value::builders::GetAssetPropertyValueInputBuilder {
        crate::operation::get_asset_property_value::builders::GetAssetPropertyValueInputBuilder::default()
    }
}

/// A builder for [`GetAssetPropertyValueInput`](crate::operation::get_asset_property_value::GetAssetPropertyValueInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetAssetPropertyValueInputBuilder {
    pub(crate) asset_id: ::std::option::Option<::std::string::String>,
    pub(crate) property_id: ::std::option::Option<::std::string::String>,
    pub(crate) property_alias: ::std::option::Option<::std::string::String>,
}
impl GetAssetPropertyValueInputBuilder {
    /// <p>The ID of the asset, in UUID format.</p>
    pub fn asset_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.asset_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the asset, in UUID format.</p>
    pub fn set_asset_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.asset_id = input;
        self
    }
    /// <p>The ID of the asset, in UUID format.</p>
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
    /// Consumes the builder and constructs a [`GetAssetPropertyValueInput`](crate::operation::get_asset_property_value::GetAssetPropertyValueInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_asset_property_value::GetAssetPropertyValueInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_asset_property_value::GetAssetPropertyValueInput {
            asset_id: self.asset_id,
            property_id: self.property_id,
            property_alias: self.property_alias,
        })
    }
}
