// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListWorkerBlocksInput {
    /// <p>Pagination token</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    #[allow(missing_docs)] // documentation missing in model
    pub max_results: ::std::option::Option<i32>,
}
impl ListWorkerBlocksInput {
    /// <p>Pagination token</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListWorkerBlocksInput {
    /// Creates a new builder-style object to manufacture [`ListWorkerBlocksInput`](crate::operation::list_worker_blocks::ListWorkerBlocksInput).
    pub fn builder() -> crate::operation::list_worker_blocks::builders::ListWorkerBlocksInputBuilder {
        crate::operation::list_worker_blocks::builders::ListWorkerBlocksInputBuilder::default()
    }
}

/// A builder for [`ListWorkerBlocksInput`](crate::operation::list_worker_blocks::ListWorkerBlocksInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListWorkerBlocksInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListWorkerBlocksInputBuilder {
    /// <p>Pagination token</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Pagination token</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>Pagination token</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListWorkerBlocksInput`](crate::operation::list_worker_blocks::ListWorkerBlocksInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_worker_blocks::ListWorkerBlocksInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_worker_blocks::ListWorkerBlocksInput {
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
