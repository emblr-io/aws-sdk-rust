// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains a part of an agent response and citations for it.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct PayloadPart {
    /// <p>A part of the agent response in bytes.</p>
    pub bytes: ::std::option::Option<::aws_smithy_types::Blob>,
    /// <p>Contains citations for a part of an agent response.</p>
    pub attribution: ::std::option::Option<crate::types::Attribution>,
}
impl PayloadPart {
    /// <p>A part of the agent response in bytes.</p>
    pub fn bytes(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.bytes.as_ref()
    }
    /// <p>Contains citations for a part of an agent response.</p>
    pub fn attribution(&self) -> ::std::option::Option<&crate::types::Attribution> {
        self.attribution.as_ref()
    }
}
impl ::std::fmt::Debug for PayloadPart {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("PayloadPart");
        formatter.field("bytes", &"*** Sensitive Data Redacted ***");
        formatter.field("attribution", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl PayloadPart {
    /// Creates a new builder-style object to manufacture [`PayloadPart`](crate::types::PayloadPart).
    pub fn builder() -> crate::types::builders::PayloadPartBuilder {
        crate::types::builders::PayloadPartBuilder::default()
    }
}

/// A builder for [`PayloadPart`](crate::types::PayloadPart).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct PayloadPartBuilder {
    pub(crate) bytes: ::std::option::Option<::aws_smithy_types::Blob>,
    pub(crate) attribution: ::std::option::Option<crate::types::Attribution>,
}
impl PayloadPartBuilder {
    /// <p>A part of the agent response in bytes.</p>
    pub fn bytes(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.bytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>A part of the agent response in bytes.</p>
    pub fn set_bytes(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.bytes = input;
        self
    }
    /// <p>A part of the agent response in bytes.</p>
    pub fn get_bytes(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.bytes
    }
    /// <p>Contains citations for a part of an agent response.</p>
    pub fn attribution(mut self, input: crate::types::Attribution) -> Self {
        self.attribution = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains citations for a part of an agent response.</p>
    pub fn set_attribution(mut self, input: ::std::option::Option<crate::types::Attribution>) -> Self {
        self.attribution = input;
        self
    }
    /// <p>Contains citations for a part of an agent response.</p>
    pub fn get_attribution(&self) -> &::std::option::Option<crate::types::Attribution> {
        &self.attribution
    }
    /// Consumes the builder and constructs a [`PayloadPart`](crate::types::PayloadPart).
    pub fn build(self) -> crate::types::PayloadPart {
        crate::types::PayloadPart {
            bytes: self.bytes,
            attribution: self.attribution,
        }
    }
}
impl ::std::fmt::Debug for PayloadPartBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("PayloadPartBuilder");
        formatter.field("bytes", &"*** Sensitive Data Redacted ***");
        formatter.field("attribution", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
