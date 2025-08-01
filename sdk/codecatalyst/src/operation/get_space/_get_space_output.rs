// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSpaceOutput {
    /// <p>The name of the space.</p>
    pub name: ::std::string::String,
    /// <p>The Amazon Web Services Region where the space exists.</p>
    pub region_name: ::std::string::String,
    /// <p>The friendly name of the space displayed to users.</p>
    pub display_name: ::std::option::Option<::std::string::String>,
    /// <p>The description of the space.</p>
    pub description: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetSpaceOutput {
    /// <p>The name of the space.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The Amazon Web Services Region where the space exists.</p>
    pub fn region_name(&self) -> &str {
        use std::ops::Deref;
        self.region_name.deref()
    }
    /// <p>The friendly name of the space displayed to users.</p>
    pub fn display_name(&self) -> ::std::option::Option<&str> {
        self.display_name.as_deref()
    }
    /// <p>The description of the space.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetSpaceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetSpaceOutput {
    /// Creates a new builder-style object to manufacture [`GetSpaceOutput`](crate::operation::get_space::GetSpaceOutput).
    pub fn builder() -> crate::operation::get_space::builders::GetSpaceOutputBuilder {
        crate::operation::get_space::builders::GetSpaceOutputBuilder::default()
    }
}

/// A builder for [`GetSpaceOutput`](crate::operation::get_space::GetSpaceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSpaceOutputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) region_name: ::std::option::Option<::std::string::String>,
    pub(crate) display_name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetSpaceOutputBuilder {
    /// <p>The name of the space.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the space.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the space.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The Amazon Web Services Region where the space exists.</p>
    /// This field is required.
    pub fn region_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.region_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services Region where the space exists.</p>
    pub fn set_region_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.region_name = input;
        self
    }
    /// <p>The Amazon Web Services Region where the space exists.</p>
    pub fn get_region_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.region_name
    }
    /// <p>The friendly name of the space displayed to users.</p>
    pub fn display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The friendly name of the space displayed to users.</p>
    pub fn set_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.display_name = input;
        self
    }
    /// <p>The friendly name of the space displayed to users.</p>
    pub fn get_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.display_name
    }
    /// <p>The description of the space.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the space.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the space.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetSpaceOutput`](crate::operation::get_space::GetSpaceOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::operation::get_space::builders::GetSpaceOutputBuilder::name)
    /// - [`region_name`](crate::operation::get_space::builders::GetSpaceOutputBuilder::region_name)
    pub fn build(self) -> ::std::result::Result<crate::operation::get_space::GetSpaceOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_space::GetSpaceOutput {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building GetSpaceOutput",
                )
            })?,
            region_name: self.region_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "region_name",
                    "region_name was not specified but it is required when building GetSpaceOutput",
                )
            })?,
            display_name: self.display_name,
            description: self.description,
            _request_id: self._request_id,
        })
    }
}
