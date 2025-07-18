// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateCustomDataIdentifierOutput {
    /// <p>The unique identifier for the custom data identifier that was created.</p>
    pub custom_data_identifier_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateCustomDataIdentifierOutput {
    /// <p>The unique identifier for the custom data identifier that was created.</p>
    pub fn custom_data_identifier_id(&self) -> ::std::option::Option<&str> {
        self.custom_data_identifier_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateCustomDataIdentifierOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateCustomDataIdentifierOutput {
    /// Creates a new builder-style object to manufacture [`CreateCustomDataIdentifierOutput`](crate::operation::create_custom_data_identifier::CreateCustomDataIdentifierOutput).
    pub fn builder() -> crate::operation::create_custom_data_identifier::builders::CreateCustomDataIdentifierOutputBuilder {
        crate::operation::create_custom_data_identifier::builders::CreateCustomDataIdentifierOutputBuilder::default()
    }
}

/// A builder for [`CreateCustomDataIdentifierOutput`](crate::operation::create_custom_data_identifier::CreateCustomDataIdentifierOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateCustomDataIdentifierOutputBuilder {
    pub(crate) custom_data_identifier_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateCustomDataIdentifierOutputBuilder {
    /// <p>The unique identifier for the custom data identifier that was created.</p>
    pub fn custom_data_identifier_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.custom_data_identifier_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the custom data identifier that was created.</p>
    pub fn set_custom_data_identifier_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.custom_data_identifier_id = input;
        self
    }
    /// <p>The unique identifier for the custom data identifier that was created.</p>
    pub fn get_custom_data_identifier_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.custom_data_identifier_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateCustomDataIdentifierOutput`](crate::operation::create_custom_data_identifier::CreateCustomDataIdentifierOutput).
    pub fn build(self) -> crate::operation::create_custom_data_identifier::CreateCustomDataIdentifierOutput {
        crate::operation::create_custom_data_identifier::CreateCustomDataIdentifierOutput {
            custom_data_identifier_id: self.custom_data_identifier_id,
            _request_id: self._request_id,
        }
    }
}
