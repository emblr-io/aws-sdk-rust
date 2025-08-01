// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetConfiguredTableOutput {
    /// <p>The retrieved configured table.</p>
    pub configured_table: ::std::option::Option<crate::types::ConfiguredTable>,
    _request_id: Option<String>,
}
impl GetConfiguredTableOutput {
    /// <p>The retrieved configured table.</p>
    pub fn configured_table(&self) -> ::std::option::Option<&crate::types::ConfiguredTable> {
        self.configured_table.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetConfiguredTableOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetConfiguredTableOutput {
    /// Creates a new builder-style object to manufacture [`GetConfiguredTableOutput`](crate::operation::get_configured_table::GetConfiguredTableOutput).
    pub fn builder() -> crate::operation::get_configured_table::builders::GetConfiguredTableOutputBuilder {
        crate::operation::get_configured_table::builders::GetConfiguredTableOutputBuilder::default()
    }
}

/// A builder for [`GetConfiguredTableOutput`](crate::operation::get_configured_table::GetConfiguredTableOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetConfiguredTableOutputBuilder {
    pub(crate) configured_table: ::std::option::Option<crate::types::ConfiguredTable>,
    _request_id: Option<String>,
}
impl GetConfiguredTableOutputBuilder {
    /// <p>The retrieved configured table.</p>
    /// This field is required.
    pub fn configured_table(mut self, input: crate::types::ConfiguredTable) -> Self {
        self.configured_table = ::std::option::Option::Some(input);
        self
    }
    /// <p>The retrieved configured table.</p>
    pub fn set_configured_table(mut self, input: ::std::option::Option<crate::types::ConfiguredTable>) -> Self {
        self.configured_table = input;
        self
    }
    /// <p>The retrieved configured table.</p>
    pub fn get_configured_table(&self) -> &::std::option::Option<crate::types::ConfiguredTable> {
        &self.configured_table
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetConfiguredTableOutput`](crate::operation::get_configured_table::GetConfiguredTableOutput).
    pub fn build(self) -> crate::operation::get_configured_table::GetConfiguredTableOutput {
        crate::operation::get_configured_table::GetConfiguredTableOutput {
            configured_table: self.configured_table,
            _request_id: self._request_id,
        }
    }
}
