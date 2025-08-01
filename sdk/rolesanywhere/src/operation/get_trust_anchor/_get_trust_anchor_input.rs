// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetTrustAnchorInput {
    /// <p>The unique identifier of the trust anchor.</p>
    pub trust_anchor_id: ::std::option::Option<::std::string::String>,
}
impl GetTrustAnchorInput {
    /// <p>The unique identifier of the trust anchor.</p>
    pub fn trust_anchor_id(&self) -> ::std::option::Option<&str> {
        self.trust_anchor_id.as_deref()
    }
}
impl GetTrustAnchorInput {
    /// Creates a new builder-style object to manufacture [`GetTrustAnchorInput`](crate::operation::get_trust_anchor::GetTrustAnchorInput).
    pub fn builder() -> crate::operation::get_trust_anchor::builders::GetTrustAnchorInputBuilder {
        crate::operation::get_trust_anchor::builders::GetTrustAnchorInputBuilder::default()
    }
}

/// A builder for [`GetTrustAnchorInput`](crate::operation::get_trust_anchor::GetTrustAnchorInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetTrustAnchorInputBuilder {
    pub(crate) trust_anchor_id: ::std::option::Option<::std::string::String>,
}
impl GetTrustAnchorInputBuilder {
    /// <p>The unique identifier of the trust anchor.</p>
    /// This field is required.
    pub fn trust_anchor_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.trust_anchor_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the trust anchor.</p>
    pub fn set_trust_anchor_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.trust_anchor_id = input;
        self
    }
    /// <p>The unique identifier of the trust anchor.</p>
    pub fn get_trust_anchor_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.trust_anchor_id
    }
    /// Consumes the builder and constructs a [`GetTrustAnchorInput`](crate::operation::get_trust_anchor::GetTrustAnchorInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_trust_anchor::GetTrustAnchorInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_trust_anchor::GetTrustAnchorInput {
            trust_anchor_id: self.trust_anchor_id,
        })
    }
}
