// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The input for the DeleteCertificate operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteCertificateInput {
    /// <p>The ID of the certificate. (The last part of the certificate ARN contains the certificate ID.)</p>
    pub certificate_id: ::std::option::Option<::std::string::String>,
    /// <p>Forces the deletion of a certificate if it is inactive and is not attached to an IoT thing.</p>
    pub force_delete: ::std::option::Option<bool>,
}
impl DeleteCertificateInput {
    /// <p>The ID of the certificate. (The last part of the certificate ARN contains the certificate ID.)</p>
    pub fn certificate_id(&self) -> ::std::option::Option<&str> {
        self.certificate_id.as_deref()
    }
    /// <p>Forces the deletion of a certificate if it is inactive and is not attached to an IoT thing.</p>
    pub fn force_delete(&self) -> ::std::option::Option<bool> {
        self.force_delete
    }
}
impl DeleteCertificateInput {
    /// Creates a new builder-style object to manufacture [`DeleteCertificateInput`](crate::operation::delete_certificate::DeleteCertificateInput).
    pub fn builder() -> crate::operation::delete_certificate::builders::DeleteCertificateInputBuilder {
        crate::operation::delete_certificate::builders::DeleteCertificateInputBuilder::default()
    }
}

/// A builder for [`DeleteCertificateInput`](crate::operation::delete_certificate::DeleteCertificateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteCertificateInputBuilder {
    pub(crate) certificate_id: ::std::option::Option<::std::string::String>,
    pub(crate) force_delete: ::std::option::Option<bool>,
}
impl DeleteCertificateInputBuilder {
    /// <p>The ID of the certificate. (The last part of the certificate ARN contains the certificate ID.)</p>
    /// This field is required.
    pub fn certificate_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the certificate. (The last part of the certificate ARN contains the certificate ID.)</p>
    pub fn set_certificate_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_id = input;
        self
    }
    /// <p>The ID of the certificate. (The last part of the certificate ARN contains the certificate ID.)</p>
    pub fn get_certificate_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_id
    }
    /// <p>Forces the deletion of a certificate if it is inactive and is not attached to an IoT thing.</p>
    pub fn force_delete(mut self, input: bool) -> Self {
        self.force_delete = ::std::option::Option::Some(input);
        self
    }
    /// <p>Forces the deletion of a certificate if it is inactive and is not attached to an IoT thing.</p>
    pub fn set_force_delete(mut self, input: ::std::option::Option<bool>) -> Self {
        self.force_delete = input;
        self
    }
    /// <p>Forces the deletion of a certificate if it is inactive and is not attached to an IoT thing.</p>
    pub fn get_force_delete(&self) -> &::std::option::Option<bool> {
        &self.force_delete
    }
    /// Consumes the builder and constructs a [`DeleteCertificateInput`](crate::operation::delete_certificate::DeleteCertificateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_certificate::DeleteCertificateInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_certificate::DeleteCertificateInput {
            certificate_id: self.certificate_id,
            force_delete: self.force_delete,
        })
    }
}
