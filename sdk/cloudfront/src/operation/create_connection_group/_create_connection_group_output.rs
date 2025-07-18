// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateConnectionGroupOutput {
    /// <p>The connection group that you created.</p>
    pub connection_group: ::std::option::Option<crate::types::ConnectionGroup>,
    /// <p>The current version of the connection group.</p>
    pub e_tag: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateConnectionGroupOutput {
    /// <p>The connection group that you created.</p>
    pub fn connection_group(&self) -> ::std::option::Option<&crate::types::ConnectionGroup> {
        self.connection_group.as_ref()
    }
    /// <p>The current version of the connection group.</p>
    pub fn e_tag(&self) -> ::std::option::Option<&str> {
        self.e_tag.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateConnectionGroupOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateConnectionGroupOutput {
    /// Creates a new builder-style object to manufacture [`CreateConnectionGroupOutput`](crate::operation::create_connection_group::CreateConnectionGroupOutput).
    pub fn builder() -> crate::operation::create_connection_group::builders::CreateConnectionGroupOutputBuilder {
        crate::operation::create_connection_group::builders::CreateConnectionGroupOutputBuilder::default()
    }
}

/// A builder for [`CreateConnectionGroupOutput`](crate::operation::create_connection_group::CreateConnectionGroupOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateConnectionGroupOutputBuilder {
    pub(crate) connection_group: ::std::option::Option<crate::types::ConnectionGroup>,
    pub(crate) e_tag: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateConnectionGroupOutputBuilder {
    /// <p>The connection group that you created.</p>
    pub fn connection_group(mut self, input: crate::types::ConnectionGroup) -> Self {
        self.connection_group = ::std::option::Option::Some(input);
        self
    }
    /// <p>The connection group that you created.</p>
    pub fn set_connection_group(mut self, input: ::std::option::Option<crate::types::ConnectionGroup>) -> Self {
        self.connection_group = input;
        self
    }
    /// <p>The connection group that you created.</p>
    pub fn get_connection_group(&self) -> &::std::option::Option<crate::types::ConnectionGroup> {
        &self.connection_group
    }
    /// <p>The current version of the connection group.</p>
    pub fn e_tag(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.e_tag = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The current version of the connection group.</p>
    pub fn set_e_tag(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.e_tag = input;
        self
    }
    /// <p>The current version of the connection group.</p>
    pub fn get_e_tag(&self) -> &::std::option::Option<::std::string::String> {
        &self.e_tag
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateConnectionGroupOutput`](crate::operation::create_connection_group::CreateConnectionGroupOutput).
    pub fn build(self) -> crate::operation::create_connection_group::CreateConnectionGroupOutput {
        crate::operation::create_connection_group::CreateConnectionGroupOutput {
            connection_group: self.connection_group,
            e_tag: self.e_tag,
            _request_id: self._request_id,
        }
    }
}
