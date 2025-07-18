// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteKxDataviewInput {
    /// <p>A unique identifier for the kdb environment, from where you want to delete the dataview.</p>
    pub environment_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the database whose dataview you want to delete.</p>
    pub database_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the dataview that you want to delete.</p>
    pub dataview_name: ::std::option::Option<::std::string::String>,
    /// <p>A token that ensures idempotency. This token expires in 10 minutes.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl DeleteKxDataviewInput {
    /// <p>A unique identifier for the kdb environment, from where you want to delete the dataview.</p>
    pub fn environment_id(&self) -> ::std::option::Option<&str> {
        self.environment_id.as_deref()
    }
    /// <p>The name of the database whose dataview you want to delete.</p>
    pub fn database_name(&self) -> ::std::option::Option<&str> {
        self.database_name.as_deref()
    }
    /// <p>The name of the dataview that you want to delete.</p>
    pub fn dataview_name(&self) -> ::std::option::Option<&str> {
        self.dataview_name.as_deref()
    }
    /// <p>A token that ensures idempotency. This token expires in 10 minutes.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl DeleteKxDataviewInput {
    /// Creates a new builder-style object to manufacture [`DeleteKxDataviewInput`](crate::operation::delete_kx_dataview::DeleteKxDataviewInput).
    pub fn builder() -> crate::operation::delete_kx_dataview::builders::DeleteKxDataviewInputBuilder {
        crate::operation::delete_kx_dataview::builders::DeleteKxDataviewInputBuilder::default()
    }
}

/// A builder for [`DeleteKxDataviewInput`](crate::operation::delete_kx_dataview::DeleteKxDataviewInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteKxDataviewInputBuilder {
    pub(crate) environment_id: ::std::option::Option<::std::string::String>,
    pub(crate) database_name: ::std::option::Option<::std::string::String>,
    pub(crate) dataview_name: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl DeleteKxDataviewInputBuilder {
    /// <p>A unique identifier for the kdb environment, from where you want to delete the dataview.</p>
    /// This field is required.
    pub fn environment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.environment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the kdb environment, from where you want to delete the dataview.</p>
    pub fn set_environment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.environment_id = input;
        self
    }
    /// <p>A unique identifier for the kdb environment, from where you want to delete the dataview.</p>
    pub fn get_environment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.environment_id
    }
    /// <p>The name of the database whose dataview you want to delete.</p>
    /// This field is required.
    pub fn database_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.database_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the database whose dataview you want to delete.</p>
    pub fn set_database_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.database_name = input;
        self
    }
    /// <p>The name of the database whose dataview you want to delete.</p>
    pub fn get_database_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.database_name
    }
    /// <p>The name of the dataview that you want to delete.</p>
    /// This field is required.
    pub fn dataview_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dataview_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the dataview that you want to delete.</p>
    pub fn set_dataview_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dataview_name = input;
        self
    }
    /// <p>The name of the dataview that you want to delete.</p>
    pub fn get_dataview_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.dataview_name
    }
    /// <p>A token that ensures idempotency. This token expires in 10 minutes.</p>
    /// This field is required.
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token that ensures idempotency. This token expires in 10 minutes.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A token that ensures idempotency. This token expires in 10 minutes.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`DeleteKxDataviewInput`](crate::operation::delete_kx_dataview::DeleteKxDataviewInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_kx_dataview::DeleteKxDataviewInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_kx_dataview::DeleteKxDataviewInput {
            environment_id: self.environment_id,
            database_name: self.database_name,
            dataview_name: self.dataview_name,
            client_token: self.client_token,
        })
    }
}
