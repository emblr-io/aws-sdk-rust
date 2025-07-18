// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ImportHostKeyOutput {
    /// <p>Returns the server identifier that contains the imported key.</p>
    pub server_id: ::std::string::String,
    /// <p>Returns the host key identifier for the imported key.</p>
    pub host_key_id: ::std::string::String,
    _request_id: Option<String>,
}
impl ImportHostKeyOutput {
    /// <p>Returns the server identifier that contains the imported key.</p>
    pub fn server_id(&self) -> &str {
        use std::ops::Deref;
        self.server_id.deref()
    }
    /// <p>Returns the host key identifier for the imported key.</p>
    pub fn host_key_id(&self) -> &str {
        use std::ops::Deref;
        self.host_key_id.deref()
    }
}
impl ::aws_types::request_id::RequestId for ImportHostKeyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ImportHostKeyOutput {
    /// Creates a new builder-style object to manufacture [`ImportHostKeyOutput`](crate::operation::import_host_key::ImportHostKeyOutput).
    pub fn builder() -> crate::operation::import_host_key::builders::ImportHostKeyOutputBuilder {
        crate::operation::import_host_key::builders::ImportHostKeyOutputBuilder::default()
    }
}

/// A builder for [`ImportHostKeyOutput`](crate::operation::import_host_key::ImportHostKeyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ImportHostKeyOutputBuilder {
    pub(crate) server_id: ::std::option::Option<::std::string::String>,
    pub(crate) host_key_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ImportHostKeyOutputBuilder {
    /// <p>Returns the server identifier that contains the imported key.</p>
    /// This field is required.
    pub fn server_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.server_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Returns the server identifier that contains the imported key.</p>
    pub fn set_server_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.server_id = input;
        self
    }
    /// <p>Returns the server identifier that contains the imported key.</p>
    pub fn get_server_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.server_id
    }
    /// <p>Returns the host key identifier for the imported key.</p>
    /// This field is required.
    pub fn host_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.host_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Returns the host key identifier for the imported key.</p>
    pub fn set_host_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.host_key_id = input;
        self
    }
    /// <p>Returns the host key identifier for the imported key.</p>
    pub fn get_host_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.host_key_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ImportHostKeyOutput`](crate::operation::import_host_key::ImportHostKeyOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`server_id`](crate::operation::import_host_key::builders::ImportHostKeyOutputBuilder::server_id)
    /// - [`host_key_id`](crate::operation::import_host_key::builders::ImportHostKeyOutputBuilder::host_key_id)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::import_host_key::ImportHostKeyOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::import_host_key::ImportHostKeyOutput {
            server_id: self.server_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "server_id",
                    "server_id was not specified but it is required when building ImportHostKeyOutput",
                )
            })?,
            host_key_id: self.host_key_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "host_key_id",
                    "host_key_id was not specified but it is required when building ImportHostKeyOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
