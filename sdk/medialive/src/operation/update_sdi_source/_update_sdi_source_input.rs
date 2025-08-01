// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// A request to update the SdiSource.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateSdiSourceInput {
    /// Include this parameter only if you want to change the name of the SdiSource. Specify a name that is unique in the AWS account. We recommend you assign a name that describes the source, for example curling-cameraA. Names are case-sensitive.
    pub mode: ::std::option::Option<crate::types::SdiSourceMode>,
    /// Include this parameter only if you want to change the name of the SdiSource. Specify a name that is unique in the AWS account. We recommend you assign a name that describes the source, for example curling-cameraA. Names are case-sensitive.
    pub name: ::std::option::Option<::std::string::String>,
    /// The ID of the SdiSource
    pub sdi_source_id: ::std::option::Option<::std::string::String>,
    /// Include this parameter only if you want to change the mode. Specify the type of the SDI source: SINGLE: The source is a single-link source. QUAD: The source is one part of a quad-link source.
    pub r#type: ::std::option::Option<crate::types::SdiSourceType>,
}
impl UpdateSdiSourceInput {
    /// Include this parameter only if you want to change the name of the SdiSource. Specify a name that is unique in the AWS account. We recommend you assign a name that describes the source, for example curling-cameraA. Names are case-sensitive.
    pub fn mode(&self) -> ::std::option::Option<&crate::types::SdiSourceMode> {
        self.mode.as_ref()
    }
    /// Include this parameter only if you want to change the name of the SdiSource. Specify a name that is unique in the AWS account. We recommend you assign a name that describes the source, for example curling-cameraA. Names are case-sensitive.
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// The ID of the SdiSource
    pub fn sdi_source_id(&self) -> ::std::option::Option<&str> {
        self.sdi_source_id.as_deref()
    }
    /// Include this parameter only if you want to change the mode. Specify the type of the SDI source: SINGLE: The source is a single-link source. QUAD: The source is one part of a quad-link source.
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::SdiSourceType> {
        self.r#type.as_ref()
    }
}
impl UpdateSdiSourceInput {
    /// Creates a new builder-style object to manufacture [`UpdateSdiSourceInput`](crate::operation::update_sdi_source::UpdateSdiSourceInput).
    pub fn builder() -> crate::operation::update_sdi_source::builders::UpdateSdiSourceInputBuilder {
        crate::operation::update_sdi_source::builders::UpdateSdiSourceInputBuilder::default()
    }
}

/// A builder for [`UpdateSdiSourceInput`](crate::operation::update_sdi_source::UpdateSdiSourceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateSdiSourceInputBuilder {
    pub(crate) mode: ::std::option::Option<crate::types::SdiSourceMode>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) sdi_source_id: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::SdiSourceType>,
}
impl UpdateSdiSourceInputBuilder {
    /// Include this parameter only if you want to change the name of the SdiSource. Specify a name that is unique in the AWS account. We recommend you assign a name that describes the source, for example curling-cameraA. Names are case-sensitive.
    pub fn mode(mut self, input: crate::types::SdiSourceMode) -> Self {
        self.mode = ::std::option::Option::Some(input);
        self
    }
    /// Include this parameter only if you want to change the name of the SdiSource. Specify a name that is unique in the AWS account. We recommend you assign a name that describes the source, for example curling-cameraA. Names are case-sensitive.
    pub fn set_mode(mut self, input: ::std::option::Option<crate::types::SdiSourceMode>) -> Self {
        self.mode = input;
        self
    }
    /// Include this parameter only if you want to change the name of the SdiSource. Specify a name that is unique in the AWS account. We recommend you assign a name that describes the source, for example curling-cameraA. Names are case-sensitive.
    pub fn get_mode(&self) -> &::std::option::Option<crate::types::SdiSourceMode> {
        &self.mode
    }
    /// Include this parameter only if you want to change the name of the SdiSource. Specify a name that is unique in the AWS account. We recommend you assign a name that describes the source, for example curling-cameraA. Names are case-sensitive.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// Include this parameter only if you want to change the name of the SdiSource. Specify a name that is unique in the AWS account. We recommend you assign a name that describes the source, for example curling-cameraA. Names are case-sensitive.
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// Include this parameter only if you want to change the name of the SdiSource. Specify a name that is unique in the AWS account. We recommend you assign a name that describes the source, for example curling-cameraA. Names are case-sensitive.
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// The ID of the SdiSource
    /// This field is required.
    pub fn sdi_source_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sdi_source_id = ::std::option::Option::Some(input.into());
        self
    }
    /// The ID of the SdiSource
    pub fn set_sdi_source_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sdi_source_id = input;
        self
    }
    /// The ID of the SdiSource
    pub fn get_sdi_source_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.sdi_source_id
    }
    /// Include this parameter only if you want to change the mode. Specify the type of the SDI source: SINGLE: The source is a single-link source. QUAD: The source is one part of a quad-link source.
    pub fn r#type(mut self, input: crate::types::SdiSourceType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// Include this parameter only if you want to change the mode. Specify the type of the SDI source: SINGLE: The source is a single-link source. QUAD: The source is one part of a quad-link source.
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::SdiSourceType>) -> Self {
        self.r#type = input;
        self
    }
    /// Include this parameter only if you want to change the mode. Specify the type of the SDI source: SINGLE: The source is a single-link source. QUAD: The source is one part of a quad-link source.
    pub fn get_type(&self) -> &::std::option::Option<crate::types::SdiSourceType> {
        &self.r#type
    }
    /// Consumes the builder and constructs a [`UpdateSdiSourceInput`](crate::operation::update_sdi_source::UpdateSdiSourceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_sdi_source::UpdateSdiSourceInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_sdi_source::UpdateSdiSourceInput {
            mode: self.mode,
            name: self.name,
            sdi_source_id: self.sdi_source_id,
            r#type: self.r#type,
        })
    }
}
