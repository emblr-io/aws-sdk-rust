// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteTapePoolInput {
    /// <p>The Amazon Resource Name (ARN) of the custom tape pool to delete.</p>
    pub pool_arn: ::std::option::Option<::std::string::String>,
}
impl DeleteTapePoolInput {
    /// <p>The Amazon Resource Name (ARN) of the custom tape pool to delete.</p>
    pub fn pool_arn(&self) -> ::std::option::Option<&str> {
        self.pool_arn.as_deref()
    }
}
impl DeleteTapePoolInput {
    /// Creates a new builder-style object to manufacture [`DeleteTapePoolInput`](crate::operation::delete_tape_pool::DeleteTapePoolInput).
    pub fn builder() -> crate::operation::delete_tape_pool::builders::DeleteTapePoolInputBuilder {
        crate::operation::delete_tape_pool::builders::DeleteTapePoolInputBuilder::default()
    }
}

/// A builder for [`DeleteTapePoolInput`](crate::operation::delete_tape_pool::DeleteTapePoolInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteTapePoolInputBuilder {
    pub(crate) pool_arn: ::std::option::Option<::std::string::String>,
}
impl DeleteTapePoolInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the custom tape pool to delete.</p>
    /// This field is required.
    pub fn pool_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pool_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the custom tape pool to delete.</p>
    pub fn set_pool_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pool_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the custom tape pool to delete.</p>
    pub fn get_pool_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.pool_arn
    }
    /// Consumes the builder and constructs a [`DeleteTapePoolInput`](crate::operation::delete_tape_pool::DeleteTapePoolInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_tape_pool::DeleteTapePoolInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_tape_pool::DeleteTapePoolInput { pool_arn: self.pool_arn })
    }
}
