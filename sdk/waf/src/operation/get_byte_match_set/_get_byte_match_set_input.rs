// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetByteMatchSetInput {
    /// <p>The <code>ByteMatchSetId</code> of the <code>ByteMatchSet</code> that you want to get. <code>ByteMatchSetId</code> is returned by <code>CreateByteMatchSet</code> and by <code>ListByteMatchSets</code>.</p>
    pub byte_match_set_id: ::std::option::Option<::std::string::String>,
}
impl GetByteMatchSetInput {
    /// <p>The <code>ByteMatchSetId</code> of the <code>ByteMatchSet</code> that you want to get. <code>ByteMatchSetId</code> is returned by <code>CreateByteMatchSet</code> and by <code>ListByteMatchSets</code>.</p>
    pub fn byte_match_set_id(&self) -> ::std::option::Option<&str> {
        self.byte_match_set_id.as_deref()
    }
}
impl GetByteMatchSetInput {
    /// Creates a new builder-style object to manufacture [`GetByteMatchSetInput`](crate::operation::get_byte_match_set::GetByteMatchSetInput).
    pub fn builder() -> crate::operation::get_byte_match_set::builders::GetByteMatchSetInputBuilder {
        crate::operation::get_byte_match_set::builders::GetByteMatchSetInputBuilder::default()
    }
}

/// A builder for [`GetByteMatchSetInput`](crate::operation::get_byte_match_set::GetByteMatchSetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetByteMatchSetInputBuilder {
    pub(crate) byte_match_set_id: ::std::option::Option<::std::string::String>,
}
impl GetByteMatchSetInputBuilder {
    /// <p>The <code>ByteMatchSetId</code> of the <code>ByteMatchSet</code> that you want to get. <code>ByteMatchSetId</code> is returned by <code>CreateByteMatchSet</code> and by <code>ListByteMatchSets</code>.</p>
    /// This field is required.
    pub fn byte_match_set_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.byte_match_set_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>ByteMatchSetId</code> of the <code>ByteMatchSet</code> that you want to get. <code>ByteMatchSetId</code> is returned by <code>CreateByteMatchSet</code> and by <code>ListByteMatchSets</code>.</p>
    pub fn set_byte_match_set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.byte_match_set_id = input;
        self
    }
    /// <p>The <code>ByteMatchSetId</code> of the <code>ByteMatchSet</code> that you want to get. <code>ByteMatchSetId</code> is returned by <code>CreateByteMatchSet</code> and by <code>ListByteMatchSets</code>.</p>
    pub fn get_byte_match_set_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.byte_match_set_id
    }
    /// Consumes the builder and constructs a [`GetByteMatchSetInput`](crate::operation::get_byte_match_set::GetByteMatchSetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_byte_match_set::GetByteMatchSetInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_byte_match_set::GetByteMatchSetInput {
            byte_match_set_id: self.byte_match_set_id,
        })
    }
}
