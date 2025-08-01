// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the signature for a file.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CodeSigningSignature {
    /// <p>A base64 encoded binary representation of the code signing signature.</p>
    pub inline_document: ::std::option::Option<::aws_smithy_types::Blob>,
}
impl CodeSigningSignature {
    /// <p>A base64 encoded binary representation of the code signing signature.</p>
    pub fn inline_document(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.inline_document.as_ref()
    }
}
impl CodeSigningSignature {
    /// Creates a new builder-style object to manufacture [`CodeSigningSignature`](crate::types::CodeSigningSignature).
    pub fn builder() -> crate::types::builders::CodeSigningSignatureBuilder {
        crate::types::builders::CodeSigningSignatureBuilder::default()
    }
}

/// A builder for [`CodeSigningSignature`](crate::types::CodeSigningSignature).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CodeSigningSignatureBuilder {
    pub(crate) inline_document: ::std::option::Option<::aws_smithy_types::Blob>,
}
impl CodeSigningSignatureBuilder {
    /// <p>A base64 encoded binary representation of the code signing signature.</p>
    pub fn inline_document(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.inline_document = ::std::option::Option::Some(input);
        self
    }
    /// <p>A base64 encoded binary representation of the code signing signature.</p>
    pub fn set_inline_document(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.inline_document = input;
        self
    }
    /// <p>A base64 encoded binary representation of the code signing signature.</p>
    pub fn get_inline_document(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.inline_document
    }
    /// Consumes the builder and constructs a [`CodeSigningSignature`](crate::types::CodeSigningSignature).
    pub fn build(self) -> crate::types::CodeSigningSignature {
        crate::types::CodeSigningSignature {
            inline_document: self.inline_document,
        }
    }
}
