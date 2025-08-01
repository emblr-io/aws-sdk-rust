// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteConnectionInput {
    /// <p>The ID of the global network.</p>
    pub global_network_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the connection.</p>
    pub connection_id: ::std::option::Option<::std::string::String>,
}
impl DeleteConnectionInput {
    /// <p>The ID of the global network.</p>
    pub fn global_network_id(&self) -> ::std::option::Option<&str> {
        self.global_network_id.as_deref()
    }
    /// <p>The ID of the connection.</p>
    pub fn connection_id(&self) -> ::std::option::Option<&str> {
        self.connection_id.as_deref()
    }
}
impl DeleteConnectionInput {
    /// Creates a new builder-style object to manufacture [`DeleteConnectionInput`](crate::operation::delete_connection::DeleteConnectionInput).
    pub fn builder() -> crate::operation::delete_connection::builders::DeleteConnectionInputBuilder {
        crate::operation::delete_connection::builders::DeleteConnectionInputBuilder::default()
    }
}

/// A builder for [`DeleteConnectionInput`](crate::operation::delete_connection::DeleteConnectionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteConnectionInputBuilder {
    pub(crate) global_network_id: ::std::option::Option<::std::string::String>,
    pub(crate) connection_id: ::std::option::Option<::std::string::String>,
}
impl DeleteConnectionInputBuilder {
    /// <p>The ID of the global network.</p>
    /// This field is required.
    pub fn global_network_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.global_network_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the global network.</p>
    pub fn set_global_network_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.global_network_id = input;
        self
    }
    /// <p>The ID of the global network.</p>
    pub fn get_global_network_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.global_network_id
    }
    /// <p>The ID of the connection.</p>
    /// This field is required.
    pub fn connection_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connection_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the connection.</p>
    pub fn set_connection_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connection_id = input;
        self
    }
    /// <p>The ID of the connection.</p>
    pub fn get_connection_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.connection_id
    }
    /// Consumes the builder and constructs a [`DeleteConnectionInput`](crate::operation::delete_connection::DeleteConnectionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_connection::DeleteConnectionInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_connection::DeleteConnectionInput {
            global_network_id: self.global_network_id,
            connection_id: self.connection_id,
        })
    }
}
