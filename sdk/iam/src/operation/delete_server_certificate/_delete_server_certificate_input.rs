// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteServerCertificateInput {
    /// <p>The name of the server certificate you want to delete.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    pub server_certificate_name: ::std::option::Option<::std::string::String>,
}
impl DeleteServerCertificateInput {
    /// <p>The name of the server certificate you want to delete.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    pub fn server_certificate_name(&self) -> ::std::option::Option<&str> {
        self.server_certificate_name.as_deref()
    }
}
impl DeleteServerCertificateInput {
    /// Creates a new builder-style object to manufacture [`DeleteServerCertificateInput`](crate::operation::delete_server_certificate::DeleteServerCertificateInput).
    pub fn builder() -> crate::operation::delete_server_certificate::builders::DeleteServerCertificateInputBuilder {
        crate::operation::delete_server_certificate::builders::DeleteServerCertificateInputBuilder::default()
    }
}

/// A builder for [`DeleteServerCertificateInput`](crate::operation::delete_server_certificate::DeleteServerCertificateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteServerCertificateInputBuilder {
    pub(crate) server_certificate_name: ::std::option::Option<::std::string::String>,
}
impl DeleteServerCertificateInputBuilder {
    /// <p>The name of the server certificate you want to delete.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    /// This field is required.
    pub fn server_certificate_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.server_certificate_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the server certificate you want to delete.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    pub fn set_server_certificate_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.server_certificate_name = input;
        self
    }
    /// <p>The name of the server certificate you want to delete.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    pub fn get_server_certificate_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.server_certificate_name
    }
    /// Consumes the builder and constructs a [`DeleteServerCertificateInput`](crate::operation::delete_server_certificate::DeleteServerCertificateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_server_certificate::DeleteServerCertificateInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_server_certificate::DeleteServerCertificateInput {
            server_certificate_name: self.server_certificate_name,
        })
    }
}
