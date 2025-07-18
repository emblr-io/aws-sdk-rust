// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeletePackageInput {
    /// <p>The name of the target software package.</p>
    pub package_name: ::std::option::Option<::std::string::String>,
    /// <p>A unique case-sensitive identifier that you can provide to ensure the idempotency of the request. Don't reuse this client token if a new idempotent request is required.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl DeletePackageInput {
    /// <p>The name of the target software package.</p>
    pub fn package_name(&self) -> ::std::option::Option<&str> {
        self.package_name.as_deref()
    }
    /// <p>A unique case-sensitive identifier that you can provide to ensure the idempotency of the request. Don't reuse this client token if a new idempotent request is required.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl DeletePackageInput {
    /// Creates a new builder-style object to manufacture [`DeletePackageInput`](crate::operation::delete_package::DeletePackageInput).
    pub fn builder() -> crate::operation::delete_package::builders::DeletePackageInputBuilder {
        crate::operation::delete_package::builders::DeletePackageInputBuilder::default()
    }
}

/// A builder for [`DeletePackageInput`](crate::operation::delete_package::DeletePackageInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeletePackageInputBuilder {
    pub(crate) package_name: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl DeletePackageInputBuilder {
    /// <p>The name of the target software package.</p>
    /// This field is required.
    pub fn package_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.package_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the target software package.</p>
    pub fn set_package_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.package_name = input;
        self
    }
    /// <p>The name of the target software package.</p>
    pub fn get_package_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.package_name
    }
    /// <p>A unique case-sensitive identifier that you can provide to ensure the idempotency of the request. Don't reuse this client token if a new idempotent request is required.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique case-sensitive identifier that you can provide to ensure the idempotency of the request. Don't reuse this client token if a new idempotent request is required.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique case-sensitive identifier that you can provide to ensure the idempotency of the request. Don't reuse this client token if a new idempotent request is required.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`DeletePackageInput`](crate::operation::delete_package::DeletePackageInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_package::DeletePackageInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_package::DeletePackageInput {
            package_name: self.package_name,
            client_token: self.client_token,
        })
    }
}
