// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisassociateKmsKeyOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DisassociateKmsKeyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DisassociateKmsKeyOutput {
    /// Creates a new builder-style object to manufacture [`DisassociateKmsKeyOutput`](crate::operation::disassociate_kms_key::DisassociateKmsKeyOutput).
    pub fn builder() -> crate::operation::disassociate_kms_key::builders::DisassociateKmsKeyOutputBuilder {
        crate::operation::disassociate_kms_key::builders::DisassociateKmsKeyOutputBuilder::default()
    }
}

/// A builder for [`DisassociateKmsKeyOutput`](crate::operation::disassociate_kms_key::DisassociateKmsKeyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisassociateKmsKeyOutputBuilder {
    _request_id: Option<String>,
}
impl DisassociateKmsKeyOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DisassociateKmsKeyOutput`](crate::operation::disassociate_kms_key::DisassociateKmsKeyOutput).
    pub fn build(self) -> crate::operation::disassociate_kms_key::DisassociateKmsKeyOutput {
        crate::operation::disassociate_kms_key::DisassociateKmsKeyOutput {
            _request_id: self._request_id,
        }
    }
}
