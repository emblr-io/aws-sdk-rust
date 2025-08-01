// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeCopyProductStatusInput {
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub accept_language: ::std::option::Option<::std::string::String>,
    /// <p>The token for the copy product operation. This token is returned by <code>CopyProduct</code>.</p>
    pub copy_product_token: ::std::option::Option<::std::string::String>,
}
impl DescribeCopyProductStatusInput {
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub fn accept_language(&self) -> ::std::option::Option<&str> {
        self.accept_language.as_deref()
    }
    /// <p>The token for the copy product operation. This token is returned by <code>CopyProduct</code>.</p>
    pub fn copy_product_token(&self) -> ::std::option::Option<&str> {
        self.copy_product_token.as_deref()
    }
}
impl DescribeCopyProductStatusInput {
    /// Creates a new builder-style object to manufacture [`DescribeCopyProductStatusInput`](crate::operation::describe_copy_product_status::DescribeCopyProductStatusInput).
    pub fn builder() -> crate::operation::describe_copy_product_status::builders::DescribeCopyProductStatusInputBuilder {
        crate::operation::describe_copy_product_status::builders::DescribeCopyProductStatusInputBuilder::default()
    }
}

/// A builder for [`DescribeCopyProductStatusInput`](crate::operation::describe_copy_product_status::DescribeCopyProductStatusInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeCopyProductStatusInputBuilder {
    pub(crate) accept_language: ::std::option::Option<::std::string::String>,
    pub(crate) copy_product_token: ::std::option::Option<::std::string::String>,
}
impl DescribeCopyProductStatusInputBuilder {
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub fn accept_language(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.accept_language = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub fn set_accept_language(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.accept_language = input;
        self
    }
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub fn get_accept_language(&self) -> &::std::option::Option<::std::string::String> {
        &self.accept_language
    }
    /// <p>The token for the copy product operation. This token is returned by <code>CopyProduct</code>.</p>
    /// This field is required.
    pub fn copy_product_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.copy_product_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the copy product operation. This token is returned by <code>CopyProduct</code>.</p>
    pub fn set_copy_product_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.copy_product_token = input;
        self
    }
    /// <p>The token for the copy product operation. This token is returned by <code>CopyProduct</code>.</p>
    pub fn get_copy_product_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.copy_product_token
    }
    /// Consumes the builder and constructs a [`DescribeCopyProductStatusInput`](crate::operation::describe_copy_product_status::DescribeCopyProductStatusInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_copy_product_status::DescribeCopyProductStatusInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_copy_product_status::DescribeCopyProductStatusInput {
            accept_language: self.accept_language,
            copy_product_token: self.copy_product_token,
        })
    }
}
