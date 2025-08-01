// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteTestSetInput {
    /// <p>The test set Id of the test set to be deleted.</p>
    pub test_set_id: ::std::option::Option<::std::string::String>,
}
impl DeleteTestSetInput {
    /// <p>The test set Id of the test set to be deleted.</p>
    pub fn test_set_id(&self) -> ::std::option::Option<&str> {
        self.test_set_id.as_deref()
    }
}
impl DeleteTestSetInput {
    /// Creates a new builder-style object to manufacture [`DeleteTestSetInput`](crate::operation::delete_test_set::DeleteTestSetInput).
    pub fn builder() -> crate::operation::delete_test_set::builders::DeleteTestSetInputBuilder {
        crate::operation::delete_test_set::builders::DeleteTestSetInputBuilder::default()
    }
}

/// A builder for [`DeleteTestSetInput`](crate::operation::delete_test_set::DeleteTestSetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteTestSetInputBuilder {
    pub(crate) test_set_id: ::std::option::Option<::std::string::String>,
}
impl DeleteTestSetInputBuilder {
    /// <p>The test set Id of the test set to be deleted.</p>
    /// This field is required.
    pub fn test_set_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.test_set_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The test set Id of the test set to be deleted.</p>
    pub fn set_test_set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.test_set_id = input;
        self
    }
    /// <p>The test set Id of the test set to be deleted.</p>
    pub fn get_test_set_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.test_set_id
    }
    /// Consumes the builder and constructs a [`DeleteTestSetInput`](crate::operation::delete_test_set::DeleteTestSetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_test_set::DeleteTestSetInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_test_set::DeleteTestSetInput {
            test_set_id: self.test_set_id,
        })
    }
}
